"""The background explanation worker.

Same shape as :mod:`app.workers.scan_worker`, and running beside it:

```
claim the oldest QUEUED explanation  →  generate it  →  commit  →  repeat
                 ↓ nothing queued
              sleep a second
```

**Why a second worker rather than one worker handling both.** The two jobs have
very different durations — a scan is milliseconds to seconds, a CPU generation
is tens of seconds — and sharing a worker would mean a queue of explanations
blocking every scan behind it. Separate threads let a scan finish while the
model is still thinking, which is what a person clicking *Scan again* expects.

The duplication is real and is left in place on purpose: extracting a generic
job runner from two examples would be guessing at what a third needs. Phase 10's
patch generation is the third, and the shape will be known by then rather than
predicted.

**Each request gets its own session and its own transaction**, and the claim is
committed before the model is called — otherwise a row lock would be held for
the entire generation, and the UI could not show RUNNING until it was over.
"""

import threading
from collections.abc import Callable

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.database import SessionLocal
from app.core.logging import get_logger
from app.knowledge.embedder import Embedder, build_embedder
from app.llm.client import OllamaClient
from app.repositories.explanation_repository import ExplanationRepository
from app.services.explanation_service import ExplanationService

logger = get_logger("sentinelforge.worker")


def build_llm_client(settings: Settings) -> OllamaClient:
    return OllamaClient(
        settings.OLLAMA_BASE_URL,
        model=settings.OLLAMA_MODEL,
        timeout_seconds=settings.OLLAMA_TIMEOUT_SECONDS,
        temperature=settings.OLLAMA_TEMPERATURE,
        max_tokens=settings.OLLAMA_MAX_TOKENS,
        context_tokens=settings.OLLAMA_CONTEXT_TOKENS,
    )


class ExplanationWorker:
    """Claims queued explanation requests and generates them, one at a time."""

    def __init__(
        self,
        settings: Settings,
        session_factory: Callable[[], Session] = SessionLocal,
        *,
        embedder: Embedder | None = None,
        llm: OllamaClient | None = None,
    ) -> None:
        self.settings = settings
        self.session_factory = session_factory
        # Both are injectable so tests can drive the worker with a stub
        # embedder and a fake Ollama — neither of which the suite may depend on
        # having installed.
        self.embedder = embedder or build_embedder(settings)
        self.llm = llm or build_llm_client(settings)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # -- one unit of work --------------------------------------------------

    def tick(self) -> bool:
        """Claim and generate one explanation. True if there was work to do."""
        session = self.session_factory()
        try:
            explanations = ExplanationRepository(session)
            explanation = explanations.claim_next(
                max_attempts=self.settings.EXPLANATION_MAX_ATTEMPTS
            )
            if explanation is None:
                session.rollback()  # release the snapshot, keep nothing
                return False

            explanation_id = explanation.id
            session.commit()

            explanation = explanations.get(explanation_id)
            if explanation is None:  # pragma: no cover - deleted between claim and run
                return True
            ExplanationService(session, self.settings, self.embedder, self.llm).run(explanation)
            session.commit()
            return True
        except Exception:  # noqa: BLE001 - one bad request must not stop the worker
            logger.exception("explanation_worker_tick_failed")
            session.rollback()
            return True
        finally:
            session.close()

    def recover_stale_explanations(self) -> int:
        """Requeue requests a previous process left RUNNING. Called at startup."""
        session = self.session_factory()
        try:
            count = ExplanationRepository(session).requeue_stale(
                older_than_seconds=self.settings.EXPLANATION_STALE_AFTER_SECONDS,
                max_attempts=self.settings.EXPLANATION_MAX_ATTEMPTS,
            )
            session.commit()
            if count:
                logger.warning("stale_explanations_recovered", extra={"count": count})
            return count
        finally:
            session.close()

    # -- the loop ----------------------------------------------------------

    def run_forever(self) -> None:
        logger.info(
            "explanation_worker_started",
            extra={
                "model": self.settings.OLLAMA_MODEL,
                "poll_seconds": self.settings.EXPLANATION_POLL_INTERVAL_SECONDS,
            },
        )
        while not self._stop.is_set():
            try:
                did_work = self.tick()
            except Exception:  # pragma: no cover - tick already guards itself
                logger.exception("explanation_worker_loop_failed")
                did_work = False
            if not did_work:
                self._stop.wait(self.settings.EXPLANATION_POLL_INTERVAL_SECONDS)
        logger.info("explanation_worker_stopped")

    def start(self) -> None:
        if self._thread is not None:  # pragma: no cover - guarded by the caller
            return
        self.recover_stale_explanations()
        self._thread = threading.Thread(
            target=self.run_forever, name="sentinelforge-explanation-worker", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """Ask the loop to finish.

        The timeout is shorter than a generation on purpose: a model call
        already in flight is left to finish in its own thread, and the row it
        was working on is recovered by the next startup's sweep. Blocking
        shutdown for a minute to be tidy would be worse.
        """
        self._stop.set()
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=timeout)
            if thread.is_alive():  # pragma: no cover - a generation outlasting shutdown
                logger.warning("explanation_worker_did_not_stop_in_time")

    def drain(self, limit: int = 100) -> int:
        """Generate every queued explanation now. For tests."""
        done = 0
        while done < limit and self.tick():
            done += 1
        return done


__all__ = ["ExplanationWorker", "build_llm_client"]
