"""Proposing a fix, and refusing to call it one.

The generation is six steps, and the order is the design:

1. **Read the region** from the workspace — the finding's lines plus context,
   with the same containment check Phase 4 applies to archive members.
2. **Refuse if the code has moved.** If the line the finding points at no longer
   contains what the analyser saw, the stored copy has changed and a patch built
   from it would edit the wrong place. Better to say so than to guess.
3. **Retrieve** the Phase 7 passages, and the Phase 8 explanation if one exists.
4. **Generate** a replacement for the region — not a diff.
5. **Splice and diff**: assemble the patched file and let ``difflib`` produce
   the unified diff, which is therefore correct by construction.
6. **Check** it changes something, stays within a size budget, is not a deletion
   in disguise, and still parses where the language allows.

What this never does is write to the workspace. A patch is text with a status of
``PROPOSED``. The moment one is stored, a validation is queued for it, and only
that — applying the diff to a throwaway copy and re-scanning — can say anything
stronger.
"""

from datetime import UTC, datetime
from http import HTTPStatus

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.errors import AppError
from app.core.logging import get_logger
from app.ingestion.workspace import WorkspaceManager
from app.knowledge.embedder import Embedder
from app.llm import patch_prompt
from app.llm.client import LlmError, OllamaClient
from app.llm.contract import LlmContractError
from app.llm.patch_contract import PATCH_PROMPT_VERSION
from app.llm.patch_contract import parse as parse_patch
from app.llm.prompt import passages_from
from app.models import (
    AuditAction,
    Explanation,
    ExplanationStatus,
    Finding,
    FindingStatus,
    Patch,
    PatchStatus,
    PatchValidation,
    PatchValidationStatus,
    Repository,
    User,
)
from app.patching import diffing
from app.patching.region import Region, RegionError, read_region, reindent, splice
from app.repositories.audit_log_repository import AuditLogRepository
from app.repositories.explanation_repository import ExplanationRepository
from app.repositories.finding_repository import FindingRepository
from app.repositories.patch_repository import PatchRepository
from app.services.auth_service import RequestContext
from app.services.knowledge_service import KnowledgeBaseNotBuiltError, KnowledgeService

logger = get_logger("sentinelforge.patches")

# Rules whose snippet is redacted before storage, so it cannot be compared
# against the file to detect drift.
REDACTED_RULE_PREFIX = "SEC"

# Temperature for a retry. The first attempt runs at the configured default
# (0), because a reproducible answer is worth having. But at 0 the model is
# deterministic, so retrying a failure returns the identical failure — and the
# UI offering a "Try again" button that cannot produce anything new is a lie
# told by the interface. A retry therefore asks a slightly different question.
RETRY_TEMPERATURE = 0.3


class PatchNotFoundError(AppError):
    def __init__(self) -> None:
        super().__init__("PATCH_NOT_FOUND", "Patch not found", status_code=HTTPStatus.NOT_FOUND)


class FindingNotFoundError(AppError):
    def __init__(self) -> None:
        super().__init__("FINDING_NOT_FOUND", "Finding not found", status_code=HTTPStatus.NOT_FOUND)


class PatchAlreadyRunningError(AppError):
    def __init__(self, patch_id: int) -> None:
        super().__init__(
            "PATCH_ALREADY_RUNNING",
            f"A change is already being proposed for this finding (request {patch_id})",
            status_code=HTTPStatus.CONFLICT,
        )


class FindingNotPatchableError(AppError):
    """Some findings have no single place to change.

    A fixed finding has nothing to fix. A finding in a repository whose stored
    copy is gone has no code to read. Saying so is better than generating a
    diff against a file that is not there.
    """

    def __init__(self, reason: str) -> None:
        super().__init__("FINDING_NOT_PATCHABLE", reason, status_code=HTTPStatus.CONFLICT)


class PatchService:
    def __init__(
        self, db: Session, settings: Settings, embedder: Embedder, llm: OllamaClient
    ) -> None:
        self.db = db
        self.settings = settings
        self.patches = PatchRepository(db)
        self.findings = FindingRepository(db)
        self.explanations = ExplanationRepository(db)
        self.audit = AuditLogRepository(db)
        self.knowledge = KnowledgeService(db, settings, embedder)
        self.workspaces = WorkspaceManager(settings)
        self.llm = llm

    # -- API side ----------------------------------------------------------

    def request(self, finding_id: int, user: User, context: RequestContext) -> Patch:
        finding = self._owned_finding(finding_id, user)
        self._assert_patchable(finding)

        active = self.patches.active_for_finding(finding.id)
        if active is not None:
            raise PatchAlreadyRunningError(active.id)

        explanation = self.explanations.latest_for_finding(finding.id)
        patch = self.patches.add(
            Patch(
                finding_id=finding.id,
                requested_by_id=user.id,
                status=PatchStatus.QUEUED,
                explanation_id=(
                    explanation.id
                    if explanation is not None and explanation.status is ExplanationStatus.COMPLETED
                    else None
                ),
            )
        )
        self.audit.add(
            action=str(AuditAction.PATCH_REQUESTED),
            user_id=user.id,
            entity_type="patch",
            entity_id=str(patch.id),
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            details={"finding_id": finding.id, "rule_id": finding.rule_id},
        )
        logger.info(
            "patch_requested",
            extra={"patch_id": patch.id, "finding_id": finding.id, "user_id": user.id},
        )
        return patch

    def get(self, patch_id: int, user: User) -> Patch:
        patch = self.patches.get_for_owner(patch_id, user.id)
        if patch is None:
            raise PatchNotFoundError
        return patch

    def latest_for_finding(self, finding_id: int, user: User) -> Patch | None:
        finding = self._owned_finding(finding_id, user)
        return self.patches.latest_for_finding(finding.id)

    # -- worker side -------------------------------------------------------

    def run(self, patch: Patch) -> None:
        started = datetime.now(UTC)
        finding = self.db.get(Finding, patch.finding_id)
        try:
            if finding is None:
                raise FindingNotPatchableError("The finding no longer exists.")
            self._assert_patchable(finding)

            region = self._region_for(finding)
            patch.file_path = finding.file_path
            patch.first_line = region.first_line
            patch.last_line = region.last_line

            passages = self.knowledge.retrieve(finding)
            patch.passage_chunk_ids = [item.chunk.id for item in passages]

            self.llm.check_ready()
            # attempts is 1 on the first run, because the claim increments it.
            temperature = None if patch.attempts <= 1 else RETRY_TEMPERATURE
            patch.temperature = (
                temperature if temperature is not None else self.settings.OLLAMA_TEMPERATURE
            )
            completion = self.llm.generate(
                patch_prompt.build(
                    finding,
                    region,
                    passages_from(passages),
                    self._explanation_text(patch.explanation_id),
                ),
                system=patch_prompt.SYSTEM_PROMPT,
                temperature=temperature,
            )
            parsed = parse_patch(completion.text)
            # Recorded now, cleared on success. A refusal below is then able to
            # say what the model actually returned rather than only why it was
            # thrown away.
            # Indentation is arithmetic, so it is fixed here rather than
            # hoped for from the model.
            replacement, reindented = reindent(parsed.replacement, region.lines)
            patch.rejected_code = replacement
            patch.reindented = reindented

            after = splice(region, replacement)
            diff = diffing.build(finding.file_path, region.file_lines, after)
            diffing.check(diff, replaced_lines=len(region.lines))
            diffing.check_substance(finding.file_path, diff.added_lines)
            diffing.check_syntax(finding.file_path, after)

            patch.status = PatchStatus.PROPOSED
            patch.model = completion.model
            patch.prompt_version = PATCH_PROMPT_VERSION
            patch.prompt_tokens = completion.prompt_tokens
            patch.completion_tokens = completion.completion_tokens
            patch.diff = diff.text
            patch.rationale = parsed.rationale
            patch.lines_added = diff.added
            patch.lines_removed = diff.removed
            patch.fences_stripped = parsed.fences_stripped
            patch.gutters_stripped = parsed.gutters_stripped
            patch.rejected_code = None
            patch.error_message = None
            self._finish(patch, started)
            # Every proposal is checked, without anybody having to ask: there is
            # no window in which a diff is on screen and nothing has tried to
            # test it. The check itself runs in the validation worker.
            self.db.add(
                PatchValidation(
                    patch_id=patch.id,
                    requested_by_id=patch.requested_by_id,
                    status=PatchValidationStatus.QUEUED,
                )
            )
            self.db.flush()

            self._record(
                AuditAction.PATCH_PROPOSED,
                patch,
                details={
                    "finding_id": patch.finding_id,
                    "model": completion.model,
                    "lines_added": diff.added,
                    "lines_removed": diff.removed,
                },
            )
            logger.info(
                "patch_proposed",
                extra={
                    "patch_id": patch.id,
                    "finding_id": patch.finding_id,
                    "model": completion.model,
                    "lines_added": diff.added,
                    "lines_removed": diff.removed,
                    "duration_ms": patch.duration_ms,
                },
            )
        except diffing.PatchRejected as rejection:
            # A refusal, not a crash. The message is written for a person and
            # says which rule the proposal broke.
            self._fail(patch, started, str(rejection), "PATCH_REJECTED")
        except RegionError as error:
            self._fail(patch, started, str(error), "REGION_UNREADABLE")
        except (FindingNotPatchableError, KnowledgeBaseNotBuiltError) as error:
            self._fail(patch, started, error.message, error.code)
        except LlmContractError as error:
            self._fail(patch, started, str(error), "LLM_CONTRACT")
        except LlmError as error:
            self._fail(patch, started, error.message, error.code)
        except Exception:  # noqa: BLE001 - the worker must survive anything
            logger.exception("patch_crashed", extra={"patch_id": patch.id})
            self._fail(patch, started, "Proposing a change failed unexpectedly.", "CRASHED")

    # -- internals ---------------------------------------------------------

    def _region_for(self, finding: Finding) -> Region:
        repository = self.db.get(Repository, finding.repository_id)
        if repository is None or not repository.workspace_path:
            raise FindingNotPatchableError(
                "The stored copy of this repository is missing. Connect the code again."
            )
        workspace = self.workspaces.absolute(repository.workspace_path)
        region = read_region(workspace, finding.file_path, finding.line_start, finding.line_end)
        self._assert_code_has_not_moved(finding, region)
        return region

    def _assert_code_has_not_moved(self, finding: Finding, region: Region) -> None:
        """Refuse when the file no longer contains what the analyser saw.

        Without this, editing a file and then asking for a fix produces a diff
        against lines that have shifted — it would apply cleanly and change the
        wrong code, which is the worst outcome available here.

        Secret findings are exempt because their snippet is redacted before
        storage, so there is nothing to compare. Their line is still checked to
        be inside the file by ``read_region``.
        """
        if finding.rule_id.startswith(REDACTED_RULE_PREFIX):
            return
        snippet = (finding.snippet or "").strip()
        if not snippet:
            return
        if snippet.splitlines()[0].strip() not in region.text:
            raise FindingNotPatchableError(
                "The code has changed since this finding was recorded, so a proposed change "
                "would edit the wrong lines. Scan again first."
            )

    def _explanation_text(self, explanation_id: int | None) -> str | None:
        if explanation_id is None:
            return None
        explanation = self.db.get(Explanation, explanation_id)
        if explanation is None or explanation.status is not ExplanationStatus.COMPLETED:
            return None
        text = " ".join(part for part in (explanation.summary, explanation.remediation) if part)
        return text or None

    def _owned_finding(self, finding_id: int, user: User) -> Finding:
        finding = self.findings.get_for_owner(finding_id, user.id)
        if finding is None:
            raise FindingNotFoundError
        return finding

    def _assert_patchable(self, finding: Finding) -> None:
        if finding.status is FindingStatus.FIXED:
            raise FindingNotPatchableError(
                "This finding is already fixed, so there is nothing to change."
            )

    def _finish(self, patch: Patch, started: datetime) -> None:
        patch.finished_at = datetime.now(UTC)
        patch.duration_ms = int((patch.finished_at - started).total_seconds() * 1000)
        self.db.flush()

    def _fail(self, patch: Patch, started: datetime, message: str, code: str) -> None:
        patch.status = PatchStatus.FAILED
        patch.error_message = message
        self._finish(patch, started)
        self._record(
            AuditAction.PATCH_FAILED,
            patch,
            details={"finding_id": patch.finding_id, "reason": code},
        )
        logger.warning(
            "patch_failed",
            extra={"patch_id": patch.id, "finding_id": patch.finding_id, "reason": code},
        )

    def _record(self, action: AuditAction, patch: Patch, *, details: dict[str, object]) -> None:
        self.audit.add(
            action=str(action),
            user_id=patch.requested_by_id,
            entity_type="patch",
            entity_id=str(patch.id),
            ip_address=None,
            user_agent=None,
            request_id=None,
            details=details,
        )


__all__ = [
    "FindingNotFoundError",
    "FindingNotPatchableError",
    "PatchAlreadyRunningError",
    "PatchNotFoundError",
    "PatchService",
]
