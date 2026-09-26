"""Requesting explanations, generating them, and refusing to make things up.

Two callers, deliberately separated — the same split as scans:

* **The API** calls :meth:`ExplanationService.request`. It checks ownership,
  refuses a second request for a finding already being explained, writes a
  ``QUEUED`` row and returns. No model runs inside an HTTP request; on a CPU
  that would hold a connection open for the better part of a minute.
* **The worker** calls :meth:`ExplanationService.run`. It has no user, and
  every query it makes is unscoped by design — it is trusted code acting on a
  row the API already authorised.

The generation itself is four steps, and the order matters:

1. **Retrieve** the Phase 7 passages for this finding. If the knowledge base has
   not been built, the job *fails here* rather than continuing. An explanation
   with no sources is the exact thing this project promised not to produce, and
   producing one that merely looks fine would be worse than producing none.
2. **Build** a prompt from the finding and those numbered passages, and nothing
   else.
3. **Generate**, with a deadline.
4. **Parse** against a narrow contract, dropping invented citations and links.

Every failure is written to the row with a message safe to show the owner. A
worker that died on one bad finding would stop explaining every other one.
"""

from datetime import UTC, datetime
from http import HTTPStatus

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.errors import AppError
from app.core.logging import get_logger
from app.knowledge.embedder import Embedder
from app.llm import prompt as prompt_builder
from app.llm.client import LlmError, LlmUnavailableError, OllamaClient
from app.llm.contract import PROMPT_VERSION, LlmContractError, parse
from app.models import (
    AuditAction,
    Explanation,
    ExplanationStatus,
    Finding,
    KnowledgeChunk,
    User,
)
from app.repositories.audit_log_repository import AuditLogRepository
from app.repositories.explanation_repository import ExplanationRepository
from app.repositories.finding_repository import FindingRepository
from app.services.auth_service import RequestContext
from app.services.knowledge_service import KnowledgeBaseNotBuiltError, KnowledgeService

logger = get_logger("sentinelforge.explanations")


class ExplanationNotFoundError(AppError):
    def __init__(self) -> None:
        super().__init__(
            "EXPLANATION_NOT_FOUND", "Explanation not found", status_code=HTTPStatus.NOT_FOUND
        )


class FindingNotFoundError(AppError):
    def __init__(self) -> None:
        super().__init__("FINDING_NOT_FOUND", "Finding not found", status_code=HTTPStatus.NOT_FOUND)


class ExplanationAlreadyRunningError(AppError):
    """One at a time per finding.

    Two generations of the same finding cost a minute of CPU each and produce
    two answers that may not agree — with nothing to say which is current.
    """

    def __init__(self, explanation_id: int) -> None:
        super().__init__(
            "EXPLANATION_ALREADY_RUNNING",
            f"This finding is already being explained (request {explanation_id})",
            status_code=HTTPStatus.CONFLICT,
        )


class ExplanationService:
    def __init__(
        self,
        db: Session,
        settings: Settings,
        embedder: Embedder,
        llm: OllamaClient,
    ) -> None:
        self.db = db
        self.settings = settings
        self.explanations = ExplanationRepository(db)
        self.findings = FindingRepository(db)
        self.audit = AuditLogRepository(db)
        self.knowledge = KnowledgeService(db, settings, embedder)
        self.llm = llm

    # -- API side ----------------------------------------------------------

    def request(self, finding_id: int, user: User, context: RequestContext) -> Explanation:
        finding = self._owned_finding(finding_id, user)

        active = self.explanations.active_for_finding(finding.id)
        if active is not None:
            raise ExplanationAlreadyRunningError(active.id)

        explanation = self.explanations.add(
            Explanation(
                finding_id=finding.id,
                requested_by_id=user.id,
                status=ExplanationStatus.QUEUED,
            )
        )
        self.audit.add(
            action=str(AuditAction.EXPLANATION_REQUESTED),
            user_id=user.id,
            entity_type="explanation",
            entity_id=str(explanation.id),
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            details={"finding_id": finding.id, "rule_id": finding.rule_id},
        )
        logger.info(
            "explanation_requested",
            extra={
                "explanation_id": explanation.id,
                "finding_id": finding.id,
                "user_id": user.id,
            },
        )
        return explanation

    def get(self, explanation_id: int, user: User) -> Explanation:
        explanation = self.explanations.get_for_owner(explanation_id, user.id)
        if explanation is None:
            raise ExplanationNotFoundError
        return explanation

    def latest_for_finding(self, finding_id: int, user: User) -> Explanation | None:
        finding = self._owned_finding(finding_id, user)
        return self.explanations.latest_for_finding(finding.id)

    def citations_for(self, explanation: Explanation) -> list[tuple[int, KnowledgeChunk]]:
        """Resolve cited numbers back to the passages they refer to.

        The model only ever produced an integer. Everything shown next to it —
        the source, the title, the link — is read here, from our own knowledge
        base, using the chunk ids recorded when the prompt was built. A citation
        whose passage has since been deleted resolves to nothing and is dropped
        rather than rendered as a dead reference.
        """
        chunk_ids = explanation.passage_chunk_ids or []
        resolved: list[tuple[int, KnowledgeChunk]] = []
        for number in explanation.citations or []:
            if not 1 <= number <= len(chunk_ids):
                continue  # pragma: no cover - the contract already filtered these
            chunk = self.db.get(KnowledgeChunk, chunk_ids[number - 1])
            if chunk is not None:
                resolved.append((number, chunk))
        return resolved

    # -- worker side -------------------------------------------------------

    def run(self, explanation: Explanation) -> None:
        """Generate one explanation and record what happened."""
        started = datetime.now(UTC)
        finding = self.db.get(Finding, explanation.finding_id)
        try:
            if finding is None:
                raise _Refused("The finding no longer exists.", "FINDING_GONE")

            passages = self._passages_for(finding)
            numbered = prompt_builder.passages_from(passages)
            explanation.passage_chunk_ids = [passage.chunk.id for passage in passages]

            # Checked before generating rather than after forty seconds of
            # waiting: a model that was never pulled is a setup problem, and
            # the message says which command fixes it.
            self.llm.check_ready()
            completion = self.llm.generate(
                prompt_builder.build(finding, numbered),
                system=prompt_builder.SYSTEM_PROMPT,
            )
            parsed = parse(completion.text, passage_count=len(numbered))

            explanation.status = ExplanationStatus.COMPLETED
            explanation.model = completion.model
            explanation.prompt_version = PROMPT_VERSION
            explanation.prompt_tokens = completion.prompt_tokens
            explanation.completion_tokens = completion.completion_tokens
            explanation.summary = parsed.summary
            explanation.impact = parsed.impact
            explanation.remediation = parsed.remediation
            explanation.citations = parsed.citations
            explanation.dropped_citations = parsed.dropped_citations
            explanation.links_removed = parsed.links_removed
            explanation.error_message = None
            self._finish(explanation, started)

            self._record(
                AuditAction.EXPLANATION_COMPLETED,
                explanation,
                details={
                    "finding_id": explanation.finding_id,
                    "model": completion.model,
                    "citations": len(parsed.citations),
                    "dropped_citations": parsed.dropped_citations,
                },
            )
            logger.info(
                "explanation_completed",
                extra={
                    "explanation_id": explanation.id,
                    "finding_id": explanation.finding_id,
                    "model": completion.model,
                    "citations": len(parsed.citations),
                    "dropped_citations": parsed.dropped_citations,
                    "links_removed": parsed.links_removed,
                    "grounded": bool(parsed.citations),
                    "duration_ms": explanation.duration_ms,
                },
            )
        except _Refused as refusal:
            self._fail(explanation, started, refusal.message, refusal.code)
        except KnowledgeBaseNotBuiltError as error:
            self._fail(explanation, started, error.message, error.code)
        except LlmContractError as error:
            # Kept verbatim: the contract module writes these for a human, and
            # none of them contain model output.
            self._fail(explanation, started, str(error), "LLM_CONTRACT")
        except LlmError as error:
            self._fail(explanation, started, error.message, error.code)
        except Exception:  # noqa: BLE001 - the worker must survive anything
            logger.exception("explanation_crashed", extra={"explanation_id": explanation.id})
            self._fail(
                explanation, started, "Generating this explanation failed unexpectedly.", "CRASHED"
            )

    # -- internals ---------------------------------------------------------

    def _passages_for(self, finding: Finding):  # noqa: ANN202 - list[RetrievedPassage]
        """Retrieve the reference material, or refuse to continue without it.

        An unbuilt knowledge base is not a reason to fall back to the model's
        memory. It is a reason to stop and say so: the whole claim of this
        phase is that the explanation is grounded in indexed sources.
        """
        try:
            return self.knowledge.retrieve(finding)
        except KnowledgeBaseNotBuiltError:
            raise
        except LlmUnavailableError:  # pragma: no cover - distinct failure path
            raise

    def _owned_finding(self, finding_id: int, user: User) -> Finding:
        finding = self.findings.get_for_owner(finding_id, user.id)
        if finding is None:
            raise FindingNotFoundError
        return finding

    def _finish(self, explanation: Explanation, started: datetime) -> None:
        explanation.finished_at = datetime.now(UTC)
        explanation.duration_ms = int((explanation.finished_at - started).total_seconds() * 1000)
        self.db.flush()

    def _fail(self, explanation: Explanation, started: datetime, message: str, code: str) -> None:
        explanation.status = ExplanationStatus.FAILED
        explanation.error_message = message
        self._finish(explanation, started)
        self._record(
            AuditAction.EXPLANATION_FAILED,
            explanation,
            details={"finding_id": explanation.finding_id, "reason": code},
        )
        logger.warning(
            "explanation_failed",
            extra={
                "explanation_id": explanation.id,
                "finding_id": explanation.finding_id,
                "reason": code,
            },
        )

    def _record(
        self, action: AuditAction, explanation: Explanation, *, details: dict[str, object]
    ) -> None:
        self.audit.add(
            action=str(action),
            user_id=explanation.requested_by_id,
            entity_type="explanation",
            entity_id=str(explanation.id),
            ip_address=None,  # the worker has no request
            user_agent=None,
            request_id=None,
            details=details,
        )


class _Refused(Exception):
    """An internal refusal with a message already safe to show the owner."""

    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.message = message
        self.code = code


__all__ = [
    "ExplanationAlreadyRunningError",
    "ExplanationNotFoundError",
    "ExplanationService",
    "FindingNotFoundError",
]
