"""Queueing a validation, running it, and recording exactly what it found.

The same two-caller split as scans, explanations and patches: the API queues
and returns, the worker runs. The logic that decides the verdict lives in
:mod:`app.patching.validation` and knows nothing about the database; this
module is the part that knows which patch, which workspace and whose it is.

Three things this service is careful never to do, because each would be a way
of saying more than a re-scan of a copy can support:

* it never writes to the stored workspace — the copy is made, patched, scanned
  and deleted inside the validation module;
* it never changes the finding. A PASSED validation means the *proposed* code
  would no longer be detected. The repository's real code is unchanged, so the
  finding stays open and the risk score stays where it is until a scan of the
  real code says otherwise;
* it never records "could not be checked" as a rejection.
"""

from datetime import UTC, datetime
from http import HTTPStatus

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.errors import AppError
from app.core.logging import get_logger
from app.ingestion.workspace import WorkspaceManager
from app.models import (
    AuditAction,
    Finding,
    Patch,
    PatchStatus,
    PatchValidation,
    PatchValidationStatus,
    Repository,
    User,
)
from app.patching.validation import CannotValidate, validate
from app.repositories.audit_log_repository import AuditLogRepository
from app.repositories.patch_repository import PatchRepository
from app.repositories.patch_validation_repository import PatchValidationRepository
from app.services.auth_service import RequestContext
from app.services.patch_service import PatchNotFoundError

logger = get_logger("sentinelforge.validation")


class ValidationAlreadyRunningError(AppError):
    def __init__(self, validation_id: int) -> None:
        super().__init__(
            "VALIDATION_ALREADY_RUNNING",
            f"This change is already being checked (request {validation_id})",
            status_code=HTTPStatus.CONFLICT,
        )


class PatchNotValidatableError(AppError):
    """Only a proposal can be checked. A refused one has no diff to apply."""

    def __init__(self) -> None:
        super().__init__(
            "PATCH_NOT_VALIDATABLE",
            "Only a proposed change can be checked, and this one was never proposed.",
            status_code=HTTPStatus.CONFLICT,
        )


class PatchValidationService:
    def __init__(self, db: Session, settings: Settings) -> None:
        self.db = db
        self.settings = settings
        self.validations = PatchValidationRepository(db)
        self.patches = PatchRepository(db)
        self.audit = AuditLogRepository(db)
        self.workspaces = WorkspaceManager(settings)

    # -- API side ----------------------------------------------------------

    def request(self, patch_id: int, user: User, context: RequestContext) -> Patch:
        patch = self.patches.get_for_owner(patch_id, user.id)
        if patch is None:
            raise PatchNotFoundError
        self._assert_validatable(patch)

        active = self.validations.active_for_patch(patch.id)
        if active is not None:
            raise ValidationAlreadyRunningError(active.id)

        validation = self.validations.add(
            PatchValidation(
                patch_id=patch.id, requested_by_id=user.id, status=PatchValidationStatus.QUEUED
            )
        )
        self.audit.add(
            action=str(AuditAction.PATCH_VALIDATION_REQUESTED),
            user_id=user.id,
            entity_type="patch_validation",
            entity_id=str(validation.id),
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            details={"patch_id": patch.id, "finding_id": patch.finding_id},
        )
        logger.info(
            "validation_requested",
            extra={"validation_id": validation.id, "patch_id": patch.id, "user_id": user.id},
        )
        return patch

    def latest_for_patch(self, patch_id: int) -> PatchValidation | None:
        return self.validations.latest_for_patch(patch_id)

    # -- worker side -------------------------------------------------------

    def run(self, validation: PatchValidation) -> None:
        started = datetime.now(UTC)
        try:
            patch = self.db.get(Patch, validation.patch_id)
            if patch is None:
                raise CannotValidate("The change no longer exists.")
            self._assert_validatable(patch)
            finding = self.db.get(Finding, patch.finding_id)
            if finding is None:
                raise CannotValidate("The finding this change was for no longer exists.")
            repository = self.db.get(Repository, finding.repository_id)
            if repository is None or not repository.workspace_path:
                raise CannotValidate(
                    "The stored copy of this repository is missing. Connect the code again."
                )

            outcome = validate(
                self.workspaces.absolute(repository.workspace_path),
                # The file the *finding* is in, not a path taken from the diff.
                finding.file_path,
                patch.diff or "",
                finding.fingerprint,
                self.settings,
            )

            validation.checks = [check.as_dict() for check in outcome.checks]
            validation.findings_before = outcome.findings_before
            validation.findings_after = outcome.findings_after
            validation.also_resolved = outcome.also_resolved
            validation.new_findings = outcome.new_findings
            validation.error_message = None
            validation.status = (
                PatchValidationStatus.PASSED if outcome.passed else PatchValidationStatus.REJECTED
            )
            self._finish(validation, started)

            failed = [check.key for check in outcome.checks if check.outcome == "failed"]
            self._record(
                AuditAction.PATCH_VALIDATION_PASSED
                if outcome.passed
                else AuditAction.PATCH_VALIDATION_REJECTED,
                validation,
                details={"patch_id": patch.id, "finding_id": finding.id, "failed_checks": failed},
            )
            logger.info(
                "validation_finished",
                extra={
                    "validation_id": validation.id,
                    "patch_id": patch.id,
                    "verdict": str(validation.status),
                    "failed_checks": failed,
                    "findings_before": outcome.findings_before,
                    "findings_after": outcome.findings_after,
                    "duration_ms": validation.duration_ms,
                },
            )
        except CannotValidate as error:
            self._fail(validation, started, str(error), "CANNOT_VALIDATE")
        except PatchNotValidatableError as error:
            self._fail(validation, started, error.message, error.code)
        except Exception:  # noqa: BLE001 - the worker must survive anything
            logger.exception("validation_crashed", extra={"validation_id": validation.id})
            self._fail(validation, started, "Checking this change failed unexpectedly.", "CRASHED")

    # -- internals ---------------------------------------------------------

    def _assert_validatable(self, patch: Patch) -> None:
        if patch.status is not PatchStatus.PROPOSED or not patch.diff:
            raise PatchNotValidatableError

    def _finish(self, validation: PatchValidation, started: datetime) -> None:
        validation.finished_at = datetime.now(UTC)
        validation.duration_ms = int((validation.finished_at - started).total_seconds() * 1000)
        self.db.flush()

    def _fail(
        self, validation: PatchValidation, started: datetime, message: str, code: str
    ) -> None:
        # FAILED, never REJECTED: nothing was learned about the patch.
        validation.status = PatchValidationStatus.FAILED
        validation.error_message = message
        self._finish(validation, started)
        self._record(
            AuditAction.PATCH_VALIDATION_FAILED,
            validation,
            details={"patch_id": validation.patch_id, "reason": code},
        )
        logger.warning(
            "validation_failed",
            extra={"validation_id": validation.id, "patch_id": validation.patch_id, "reason": code},
        )

    def _record(
        self, action: AuditAction, validation: PatchValidation, *, details: dict[str, object]
    ) -> None:
        self.audit.add(
            action=str(action),
            user_id=validation.requested_by_id,
            entity_type="patch_validation",
            entity_id=str(validation.id),
            ip_address=None,
            user_agent=None,
            request_id=None,
            details=details,
        )


__all__ = [
    "PatchNotValidatableError",
    "PatchValidationService",
    "ValidationAlreadyRunningError",
]
