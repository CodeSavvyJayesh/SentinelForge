"""The background patch worker.

Third user of :class:`app.workers.job_worker.JobWorker`, and the reason that
class exists.

**Why not reuse the explanation worker.** They call the same model with similar
timings, so sharing the thread is tempting. They are separate because a queue
of patch requests must not delay explanations: a person reading a finding asks
"what is this" long before "fix it", and the first question should not wait
behind the second. Two workers also means a hung patch generation cannot stop
explanations from being produced.
"""

from collections.abc import Callable

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.database import SessionLocal
from app.knowledge.embedder import Embedder, build_embedder
from app.llm.client import OllamaClient
from app.repositories.patch_repository import PatchRepository
from app.services.patch_service import PatchService
from app.workers.explanation_worker import build_llm_client
from app.workers.job_worker import JobWorker


class PatchWorker(JobWorker):
    """Claims queued patch requests and generates them, one at a time."""

    job_name = "patch"

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
        return self.settings.PATCH_POLL_INTERVAL_SECONDS

    def claim(self, session: Session):  # noqa: ANN201
        return PatchRepository(session).claim_next(max_attempts=self.settings.PATCH_MAX_ATTEMPTS)

    def reload(self, session: Session, job_id: int):  # noqa: ANN201
        return PatchRepository(session).get(job_id)

    def run_job(self, session: Session, job) -> None:  # noqa: ANN001
        PatchService(session, self.settings, self.embedder, self.llm).run(job)

    def requeue_stale(self, session: Session) -> int:
        return PatchRepository(session).requeue_stale(
            older_than_seconds=self.settings.PATCH_STALE_AFTER_SECONDS,
            max_attempts=self.settings.PATCH_MAX_ATTEMPTS,
        )

    def recover_stale_patches(self) -> int:
        return self.recover_stale()


__all__ = ["PatchWorker"]
