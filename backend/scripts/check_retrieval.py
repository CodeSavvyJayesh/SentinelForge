"""Check what the real model actually retrieves, against the real knowledge base.

    python scripts/check_retrieval.py
    python scripts/check_retrieval.py --show 3

The automated test suite runs against a stub embedder, because loading a neural
network to prove that a database filter works would be slow and would tell you
nothing about the filter. That leaves one claim untested: *does the model put
the right passage first?* This script is how that claim is checked — with the
real model, the real vectors, and a set of findings whose correct answer is not
in dispute.

Each case names a finding the analyser could plausibly raise and the CWE whose
material must come back for it. A case fails if that CWE is absent from the top
results, and the script exits non-zero, so it can be run after every rebuild
rather than read once and forgotten.

It is a script rather than a test because it needs two things a test must not
depend on: the model installed, and a knowledge base someone has built.
"""

import argparse
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.core.config import get_settings  # noqa: E402
from app.core.database import SessionLocal  # noqa: E402
from app.knowledge.embedder import EmbeddingBackendUnavailableError, build_embedder  # noqa: E402
from app.models import Confidence, Finding, Severity  # noqa: E402
from app.services.knowledge_service import (  # noqa: E402
    KnowledgeBaseNotBuiltError,
    KnowledgeService,
    query_text,
)

# (rule, cwe, owasp, file, title, message, expected CWE in the results)
CASES: tuple[tuple[str, str, str, str, str, str, str], ...] = (
    (
        "JV003",
        "CWE-327",
        "A02:2021 Cryptographic Failures",
        "srv/Report.java",
        "Weak hash algorithm (MD5 or SHA-1)",
        "MD5 and SHA-1 are collision-broken and must not be used to prove integrity.",
        "CWE-327",
    ),
    (
        "PY010",
        "CWE-89",
        "A03:2021 Injection",
        "app/users.py",
        "SQL query built by string formatting",
        "A value formatted into SQL can change the statement's structure.",
        "CWE-89",
    ),
    (
        "PY002",
        "CWE-78",
        "A03:2021 Injection",
        "app/tasks.py",
        "subprocess called with shell=True",
        "Shell metacharacters in an interpolated value become additional commands.",
        "CWE-78",
    ),
    (
        "JS003",
        "CWE-79",
        "A03:2021 Injection",
        "web/profile.js",
        "HTML assigned from a variable",
        "Assigning to innerHTML parses the value as markup and can execute script.",
        "CWE-79",
    ),
    (
        "SEC003",
        "CWE-798",
        "A07:2021 Identification and Authentication Failures",
        "config/.env",
        "Provider API token in source",
        "A provider token committed to the repository grants access to the account.",
        "CWE-798",
    ),
    (
        "PY005",
        "CWE-502",
        "A08:2021 Software and Data Integrity Failures",
        "app/cache.py",
        "pickle used on external data",
        "Unpickling runs code contained in the payload.",
        "CWE-502",
    ),
)


def _finding(case: tuple[str, str, str, str, str, str, str]) -> Finding:
    rule_id, cwe_id, owasp, path, title, message, _ = case
    return Finding(
        id=0,
        repository_id=0,
        rule_id=rule_id,
        analyzer="check",
        title=title,
        message=message,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe_id=cwe_id,
        owasp_category=owasp,
        file_path=path,
        line_start=1,
        line_end=1,
        snippet="",
        fingerprint="check",
    )


# Sections that answer "how do I fix this?". At least one has to reach the top
# of the list, because that is the question a developer looking at a finding is
# actually asking.
REMEDIATION_SECTIONS = frozenset({"Fix", "Mitigations"})
# A list of platform names. It is worth indexing and it is never the best answer
# to anything, so seeing it first means the ranking is not working.
NEVER_FIRST = frozenset({"Applicable platforms"})


def _judge(passages, expected: str) -> list[str]:  # noqa: ANN001
    """Why this case failed, or an empty list if it passed.

    The first check — is the right CWE present — is close to tautological, and
    saying so is more useful than quietly banking it: retrieval *filters* on the
    finding's CWE, so the material is there unless the filter itself is broken.
    Worth asserting, but it tests our SQL rather than the model.

    The other two check what only the model decides: the order. Whether a query
    about fixing a weakness surfaces the mitigation text rather than the list of
    affected platforms is exactly the claim a stub embedder cannot make, and it
    is the reason this script exists at all.
    """
    reasons: list[str] = []
    if not passages:
        return ["nothing was retrieved"]

    if not any(passage.chunk.cwe_id == expected for passage in passages):
        reasons.append(f"{expected} is absent — the identifier filter is not working")

    first = passages[0].chunk.section
    if first in NEVER_FIRST:
        reasons.append(f"ranked {first!r} first, which answers no question")

    top = [passage.chunk.section for passage in passages[:3]]
    if not REMEDIATION_SECTIONS.intersection(top):
        reasons.append(f"no remediation section in the top 3 (got {', '.join(top)})")
    return reasons


def main() -> int:
    parser = argparse.ArgumentParser(description="Check retrieval quality with the real model.")
    parser.add_argument("--show", type=int, default=3, help="Passages to print per case")
    arguments = parser.parse_args()

    settings = get_settings()
    session = SessionLocal()
    try:
        service = KnowledgeService(session, settings, build_embedder(settings))
        status = service.status()
        if not status.built:
            print(
                "The knowledge base is empty. Run scripts/build_knowledge.py first.",
                file=sys.stderr,
            )
            return 2
        print(
            f"{status.documents} documents, {status.embedded_chunks} embedded passages, "
            f"model {', '.join(status.embedding_models) or 'unknown'}\n"
        )

        failures = 0
        for case in CASES:
            finding = _finding(case)
            expected = case[-1]
            try:
                passages = service.retrieve(finding)
            except (KnowledgeBaseNotBuiltError, EmbeddingBackendUnavailableError) as error:
                print(f"{finding.rule_id}: could not retrieve — {error}", file=sys.stderr)
                return 3

            reasons = _judge(passages, expected)
            failures += 1 if reasons else 0
            verdict = "PASS" if not reasons else "FAIL"
            print(f"{verdict}  {finding.rule_id}  expects {expected}")
            print(f"      query: {query_text(finding)}")
            for passage in passages[: arguments.show]:
                document = passage.chunk.document
                print(
                    f"      {passage.score:+.3f}  [{passage.matched_by:<8}] "
                    f"{document.external_id} — {passage.chunk.section}"
                )
            for reason in reasons:
                print(f"      ! {reason}")
            print()

        print(f"{len(CASES) - failures}/{len(CASES)} cases passed")
        return 1 if failures else 0
    finally:
        session.close()


if __name__ == "__main__":
    raise SystemExit(main())
