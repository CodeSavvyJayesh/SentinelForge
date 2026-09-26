"""Talking to Ollama, and failing usefully when it is not there.

Tested against a real HTTP server on a loopback port rather than a mocked
``urlopen``. Mocking the transport would test that the code calls a function;
this tests that it survives what a daemon actually does — a refused connection,
a 404, a body that is not JSON, a response that never ends.

Every failure here is one a person has to fix at a terminal, so every test also
asserts the message says which command to run.
"""

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from app.llm.client import (
    MAX_RESPONSE_BYTES,
    LlmError,
    LlmTimeoutError,
    LlmUnavailableError,
    OllamaClient,
)


class _Handler(BaseHTTPRequestHandler):
    """Serves whatever the test told it to."""

    def log_message(self, *args) -> None:  # noqa: ANN002 - silence the test output
        pass

    def _reply(self) -> None:
        behaviour = self.server.behaviour  # type: ignore[attr-defined]
        if behaviour.get("delay"):
            threading.Event().wait(behaviour["delay"])
        status = behaviour.get("status", 200)
        body = behaviour.get("body", b"{}")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        self._reply()

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        self.server.last_body = json.loads(self.rfile.read(length) or b"{}")  # type: ignore[attr-defined]
        self._reply()


class _Server:
    def __init__(self, behaviour: dict) -> None:
        self.http = HTTPServer(("127.0.0.1", 0), _Handler)
        self.http.behaviour = behaviour  # type: ignore[attr-defined]
        self.http.last_body = None  # type: ignore[attr-defined]
        # Daemon threads and a socket timeout: a handler that blocks must never
        # be able to hang the whole suite. Phase 4 learned this the hard way.
        self.http.timeout = 5
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.http.server_address[1]}"

    def close(self) -> None:
        self.http.shutdown()
        self.http.server_close()


@pytest.fixture
def serving():  # noqa: ANN201
    servers: list[_Server] = []

    def start(behaviour: dict) -> _Server:
        server = _Server(behaviour)
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.close()


def client_for(server: _Server, **kwargs) -> OllamaClient:  # noqa: ANN003
    return OllamaClient(
        server.url,
        model=kwargs.pop("model", "test-model:1b"),
        timeout_seconds=kwargs.pop("timeout_seconds", 5),
        **kwargs,
    )


# --- generation -----------------------------------------------------------


def test_a_completion_is_parsed_with_its_token_counts(serving) -> None:  # noqa: ANN001
    body = json.dumps(
        {
            "model": "test-model:1b",
            "response": '{"summary":"x"}',
            "total_duration": 2_500_000_000,
            "prompt_eval_count": 321,
            "eval_count": 45,
        }
    ).encode()
    server = serving({"body": body})

    completion = client_for(server).generate("prompt")

    assert completion.text == '{"summary":"x"}'
    assert completion.total_duration_ms == 2500
    assert completion.prompt_tokens == 321
    assert completion.completion_tokens == 45


def test_generation_asks_for_json_and_pins_the_sampler(serving) -> None:  # noqa: ANN001
    """JSON mode constrains decoding to valid syntax, and temperature 0 makes
    the same finding produce the same explanation — which is what makes a
    stored explanation worth storing."""
    server = serving({"body": json.dumps({"response": "{}"}).encode()})

    client_for(server, temperature=0.0).generate("prompt", system="rules")

    sent = server.http.last_body  # type: ignore[attr-defined]
    assert sent["format"] == "json"
    assert sent["stream"] is False
    assert sent["system"] == "rules"
    assert sent["options"]["temperature"] == 0.0


def test_an_empty_response_is_an_error_not_an_empty_explanation(serving) -> None:  # noqa: ANN001
    server = serving({"body": json.dumps({"response": "   "}).encode()})
    with pytest.raises(LlmError, match="empty response"):
        client_for(server).generate("prompt")


def test_a_body_that_is_not_json_is_reported_clearly(serving) -> None:  # noqa: ANN001
    server = serving({"body": b"<html>gateway error</html>"})
    with pytest.raises(LlmError, match="not JSON"):
        client_for(server).generate("prompt")


def test_an_oversized_response_is_refused(serving) -> None:  # noqa: ANN001
    """The daemon is trusted not to be hostile. "Trusted" and "guaranteed to
    send something sane" are different claims, and a worker reading an
    unbounded body is a worker holding unbounded memory."""
    payload = json.dumps({"response": "x" * (MAX_RESPONSE_BYTES + 10)}).encode()
    server = serving({"body": payload})
    with pytest.raises(LlmError, match="more than"):
        client_for(server).generate("prompt")


# --- things that are not running ------------------------------------------


def closed_port() -> int:
    """A loopback port nothing is listening on.

    Bound and released rather than hardcoded. Port 1 was the first attempt and
    it is refused instantly on Linux and *times out* on Windows, where the
    firewall drops rather than rejects — so the test passed at home and failed
    on the machine this project is actually developed on, having never once
    exercised the branch it was written for. A port the OS just handed back is
    refused on both.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_a_refused_connection_names_the_command_that_fixes_it() -> None:
    """By far the most common failure: Ollama simply is not running."""
    client = OllamaClient(f"http://127.0.0.1:{closed_port()}", model="m", timeout_seconds=5)
    with pytest.raises(LlmUnavailableError, match="ollama serve"):
        client.generate("prompt")


def test_a_timeout_also_points_at_a_daemon_that_may_not_be_running() -> None:
    """A connect timeout and a read timeout arrive here identically, and only
    one of them is about a slow model. The message has to serve both, or the
    Windows case sends somebody hunting a model that never started."""
    message = str(LlmTimeoutError(30, "http://localhost:11434"))
    assert "30 seconds" in message
    assert "ollama serve" in message
    assert "localhost:11434" in message


def test_a_404_from_generate_means_the_model_is_not_installed(serving) -> None:  # noqa: ANN001
    server = serving({"status": 404, "body": b'{"error":"model not found"}'})
    with pytest.raises(LlmUnavailableError, match="ollama pull"):
        client_for(server, model="missing:7b").generate("prompt")


def test_another_http_error_is_not_mistaken_for_a_missing_model(serving) -> None:  # noqa: ANN001
    server = serving({"status": 500, "body": b'{"error":"boom"}'})
    with pytest.raises(LlmError, match="HTTP 500") as caught:
        client_for(server).generate("prompt")
    assert caught.value.code == "LLM_HTTP_ERROR"


def test_a_slow_daemon_hits_the_deadline_rather_than_waiting_forever(serving) -> None:  # noqa: ANN001
    """A local model under memory pressure can take minutes. A request with no
    deadline is a worker thread gone for good."""
    server = serving({"delay": 3, "body": json.dumps({"response": "{}"}).encode()})
    with pytest.raises(LlmTimeoutError):
        client_for(server, timeout_seconds=1).generate("prompt")


# --- readiness ------------------------------------------------------------


def test_check_ready_passes_when_the_model_is_installed(serving) -> None:  # noqa: ANN001
    body = json.dumps({"models": [{"name": "test-model:1b"}, {"name": "other:7b"}]}).encode()
    server = serving({"body": body})
    client_for(server, model="test-model:1b").check_ready()  # does not raise


def test_check_ready_names_the_missing_model_and_what_is_there(serving) -> None:  # noqa: ANN001
    """Checked before generating rather than discovered forty seconds in, as a
    generic failure."""
    body = json.dumps({"models": [{"name": "llama3:8b"}]}).encode()
    server = serving({"body": body})
    with pytest.raises(LlmUnavailableError) as caught:
        client_for(server, model="qwen2.5-coder:7b").check_ready()
    assert "ollama pull qwen2.5-coder:7b" in str(caught.value)
    assert "llama3:8b" in str(caught.value)


def test_a_model_configured_without_a_tag_matches_latest(serving) -> None:  # noqa: ANN001
    """Ollama reports "mistral:latest" for what a person configured as
    "mistral". Failing on that would be pedantry with a 4 GB download attached."""
    body = json.dumps({"models": [{"name": "mistral:latest"}]}).encode()
    server = serving({"body": body})
    client_for(server, model="mistral").check_ready()


def test_a_daemon_that_answers_nonsense_to_tags_is_refused(serving) -> None:  # noqa: ANN001
    server = serving({"body": json.dumps({"models": "not-a-list"}).encode()})
    with pytest.raises(LlmUnavailableError, match="unexpected model list"):
        client_for(server).available_models()


def test_a_base_url_that_is_not_http_is_refused() -> None:
    """`urlopen` speaks file: and ftp: too. A base URL of "file:///etc/passwd"
    would have this client reading local files and parsing them as a model
    response — and OLLAMA_BASE_URL is one careless environment variable away."""
    for bad in ("file:///etc/passwd", "ftp://example.invalid", "localhost:11434"):
        with pytest.raises(LlmUnavailableError, match="must be http"):
            OllamaClient(bad, model="m", timeout_seconds=1)


def test_http_and_https_are_both_accepted() -> None:
    OllamaClient("http://localhost:11434", model="m", timeout_seconds=1)
    OllamaClient("https://ollama.internal", model="m", timeout_seconds=1)
