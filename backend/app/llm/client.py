"""Talking to a local Ollama daemon.

Written against Ollama's HTTP API directly rather than through its Python SDK.
The whole surface used here is two endpoints and a JSON body; a dependency to
wrap that would be a dependency to audit, pin and upgrade for no benefit, and
this file is where the security properties of the LLM integration live — it
should be readable in one sitting.

Three things this client is careful about, because a language model running on
the same machine is still a service that can misbehave:

* **It always has a deadline.** A local model under memory pressure can take
  minutes, and a request with no timeout is a worker thread gone forever.
* **It bounds what it will read.** A response is capped before it is parsed:
  the daemon is trusted not to be hostile, but "trusted" and "guaranteed to
  send something sane" are different claims.
* **It never guesses when something is wrong.** A daemon that is not running
  and a model that was never pulled are different problems with different
  fixes, and the error says which one happened.

Nothing here interprets the model's output. That is
:mod:`app.llm.contract`'s job, and keeping the two apart is deliberate: this
file trusts the daemon to return bytes, and nothing beyond that.
"""

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http import HTTPStatus

from app.core.logging import get_logger

logger = get_logger("sentinelforge.llm")

# Ollama replies to /api/tags on any running daemon, so it doubles as a health
# check that does not load a model.
TAGS_PATH = "/api/tags"
GENERATE_PATH = "/api/generate"

# A generated explanation is a few hundred words. This cap is far above that
# and far below "a response that exhausts memory".
MAX_RESPONSE_BYTES = 2 * 1024 * 1024

# urlopen speaks file:, ftp: and more. Only these two are a language model.
ALLOWED_SCHEMES = frozenset({"http", "https"})


class LlmError(RuntimeError):
    """Something went wrong talking to the model. Always actionable."""

    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class LlmUnavailableError(LlmError):
    """The daemon is not reachable, or the model is not installed.

    Separate from a generation failure because the fix is different: this one is
    always something the operator does at a terminal, and the message says what.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message, code="LLM_UNAVAILABLE")


class LlmTimeoutError(LlmError):
    """Nothing came back in time.

    The message covers both causes on purpose, because from here they are not
    reliably distinguishable. A *read* timeout means the model is thinking too
    slowly; a *connect* timeout means nothing is listening and the packets went
    nowhere — and on Windows a connection to a dead port times out where on
    Linux the same connection is refused instantly. Saying only "the model did
    not respond" would send somebody looking at a model that was never running.
    """

    def __init__(self, seconds: int, base_url: str | None = None) -> None:
        where = f" at {base_url}" if base_url else ""
        super().__init__(
            f"Ollama{where} did not respond within {seconds} seconds. "
            "If it is not running, start it with:  ollama serve",
            code="LLM_TIMEOUT",
        )


@dataclass(frozen=True)
class Completion:
    """What came back. ``text`` is unvalidated model output."""

    text: str
    model: str
    total_duration_ms: int
    prompt_tokens: int
    completion_tokens: int


class OllamaClient:
    def __init__(
        self,
        base_url: str,
        *,
        model: str,
        timeout_seconds: int,
        health_timeout_seconds: int = 5,
        temperature: float = 0.0,
        max_tokens: int = 800,
        context_tokens: int = 8192,
    ) -> None:
        # The scheme is checked rather than assumed. `urlopen` speaks more than
        # HTTP: a base URL of "file:///etc/passwd" would have this client
        # cheerfully reading local files and parsing them as a model response.
        # OLLAMA_BASE_URL is configuration, and configuration is one typo or one
        # careless environment variable away from being an attack.
        scheme = urllib.parse.urlparse(base_url).scheme.lower()
        if scheme not in ALLOWED_SCHEMES:
            raise LlmUnavailableError(
                f"OLLAMA_BASE_URL must be http or https, not {scheme or 'a missing scheme'!r}."
            )
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.health_timeout_seconds = health_timeout_seconds
        # Temperature 0 by default. An explanation of a vulnerability is not a
        # place for variety: the same finding should produce the same text, and
        # a reader comparing two reports should be comparing the code rather
        # than the sampler. This is also what makes a stored explanation
        # meaningful — regenerating it should not quietly say something else.
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.context_tokens = context_tokens

    # -- health ------------------------------------------------------------

    def available_models(self) -> list[str]:
        """Model names the daemon has locally. Raises if it is not running."""
        payload = self._get(TAGS_PATH, timeout=self.health_timeout_seconds)
        models = payload.get("models")
        if not isinstance(models, list):
            raise LlmUnavailableError("The Ollama daemon returned an unexpected model list.")
        return sorted(
            name for entry in models if isinstance(entry, dict) and (name := entry.get("name"))
        )

    def check_ready(self) -> None:
        """Refuse early, with the command that fixes it.

        Called before a generation job starts. Without it, a missing model is
        discovered forty seconds in, as a generic failure.
        """
        models = self.available_models()
        # Ollama reports "qwen2.5-coder:7b"; a configured name without a tag
        # means the implicit ":latest".
        wanted = self.model if ":" in self.model else f"{self.model}:latest"
        if wanted not in models and self.model not in models:
            available = ", ".join(models) or "none"
            raise LlmUnavailableError(
                f"The model {self.model!r} is not installed in Ollama (found: {available}). "
                f"Install it with:  ollama pull {self.model}"
            )

    # -- generation --------------------------------------------------------

    def generate(self, prompt: str, *, system: str | None = None) -> Completion:
        """Run one completion, in JSON mode.

        ``format: json`` makes the daemon constrain decoding to valid JSON. That
        is a guarantee about *syntax* and nothing else — the object can still
        have the wrong keys, invented citations or a thousand-word field, which
        is why every response goes through the contract module afterwards.
        """
        body = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": self.temperature,
                "num_predict": self.max_tokens,
                "num_ctx": self.context_tokens,
            },
        }
        if system:
            body["system"] = system

        payload = self._post(GENERATE_PATH, body, timeout=self.timeout_seconds)
        text = payload.get("response")
        if not isinstance(text, str) or not text.strip():
            raise LlmError("The model returned an empty response.", code="LLM_EMPTY_RESPONSE")

        return Completion(
            text=text,
            model=str(payload.get("model") or self.model),
            total_duration_ms=int(payload.get("total_duration", 0) // 1_000_000),
            prompt_tokens=int(payload.get("prompt_eval_count") or 0),
            completion_tokens=int(payload.get("eval_count") or 0),
        )

    # -- transport ---------------------------------------------------------

    def _get(self, path: str, *, timeout: int) -> dict:
        # noqa comments record that the scheme was validated in __init__.
        request = urllib.request.Request(f"{self.base_url}{path}")  # noqa: S310
        return self._request(request, timeout=timeout)

    def _post(self, path: str, body: dict, *, timeout: int) -> dict:
        request = urllib.request.Request(  # noqa: S310 - scheme validated in __init__
            f"{self.base_url}{path}",
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        return self._request(request, timeout=timeout)

    def _request(self, request: urllib.request.Request, *, timeout: int) -> dict:
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            # 404 from /api/generate is Ollama's way of saying "no such model".
            if exc.code == HTTPStatus.NOT_FOUND:
                raise LlmUnavailableError(
                    f"Ollama does not have the model {self.model!r}. "
                    f"Install it with:  ollama pull {self.model}"
                ) from exc
            raise LlmError(
                f"Ollama refused the request (HTTP {exc.code}).", code="LLM_HTTP_ERROR"
            ) from exc
        except TimeoutError as exc:
            raise LlmTimeoutError(timeout, self.base_url) from exc
        except urllib.error.URLError as exc:
            # Covers "connection refused" — by far the most common cause, and
            # the one with the simplest fix.
            if isinstance(exc.reason, TimeoutError):
                raise LlmTimeoutError(timeout, self.base_url) from exc
            raise LlmUnavailableError(
                f"Could not reach Ollama at {self.base_url} ({exc.reason}). "
                "Start it with:  ollama serve"
            ) from exc
        except OSError as exc:
            raise LlmUnavailableError(f"Could not reach Ollama at {self.base_url}: {exc}") from exc

        if len(raw) > MAX_RESPONSE_BYTES:
            raise LlmError(
                f"Ollama sent more than {MAX_RESPONSE_BYTES} bytes.", code="LLM_RESPONSE_TOO_LARGE"
            )
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise LlmError("Ollama sent a response that is not JSON.", code="LLM_BAD_JSON") from exc
        if not isinstance(payload, dict):
            raise LlmError("Ollama sent a JSON value that is not an object.", code="LLM_BAD_JSON")
        return payload


__all__ = [
    "MAX_RESPONSE_BYTES",
    "Completion",
    "LlmError",
    "LlmTimeoutError",
    "LlmUnavailableError",
    "OllamaClient",
]
