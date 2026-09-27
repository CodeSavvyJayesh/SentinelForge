"""The background explanation worker.

Shares its loop with every other job in the project — see
:class:`app.workers.job_worker.JobWorker`. What stays here is the wiring an
explanation needs and the others do not: an embedding model for retrieval and a
client for the local LLM, both injectable so the tests can drive the worker
without either installed.

**Why a separate worker rather than more work for the scan one.** A scan is
milliseconds to seconds; a CPU generation is tens of seconds. Sharing a worker
would put every scan behind a queue of model calls, so *Scan again* would look
frozen while something unrelated was being explained.
"""

from collections.abc import Callable

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.database import SessionLocal
from app.knowledge.embedder import Embedder, build_embedder
from app.llm.client import OllamaClient
from app.repositories.explanation_repository import ExplanationRepository
from app.services.explanation_service import ExplanationService
from app.workers.job_worker import JobWorker


def build_llm_client(settings: Settings) -> OllamaClient:
    return OllamaClient(
        settings.OLLAMA_BASE_URL,
        model=settings.OLLAMA_MODEL,
        timeout_seconds=settings.OLLAMA_TIMEOUT_SECONDS,
        temperature=settings.OLLAMA_TEMPERATURE,
        max_tokens=settings.OLLAMA_MAX_TOKENS,
        context_tokens=settings.OLLAMA_CONTEXT_TOKENS,
    )


class ExplanationWorker(JobWorker):
    """Claims queued explanation requests and generates them, one at a time."""

    job_name = "explanation"

    def __init__(
        self,
        settings: Settings,
        session_factory: Callable[[], Session] = SessionLocal,
        *,
        embedder: Embedder | None = None,
        llm: OllamaClient | None = None,
    ) -> None:
        super().__init__(settings, session_factory)
        self.embedder = embedder or build_embedder(settings)
        self.llm = llm or build_llm_client(settings)

    @property
    def poll_interval(self) -> float:
        return self.settings.EXPLANATION_POLL_INTERVAL_SECONDS

    def claim(self, session: Session):  # noqa: ANN201
        return ExplanationRepository(session).claim_next(
            max_attempts=self.settings.EXPLANATION_MAX_ATTEMPTS
        )

    def reload(self, session: Session, job_id: int):  # noqa: ANN201
        return ExplanationRepository(session).get(job_id)

    def run_job(self, session: Session, job) -> None:  # noqa: ANN001
        ExplanationService(session, self.settings, self.embedder, self.llm).run(job)

    def requeue_stale(self, session: Session) -> int:
        return ExplanationRepository(session).requeue_stale(
            older_than_seconds=self.settings.EXPLANATION_STALE_AFTER_SECONDS,
            max_attempts=self.settings.EXPLANATION_MAX_ATTEMPTS,
        )

    def recover_stale_explanations(self) -> int:
        return self.recover_stale()


__all__ = ["ExplanationWorker", "build_llm_client"]
