"""Build the security knowledge base from the downloaded sources.

    python scripts/build_knowledge.py
    python scripts/build_knowledge.py --sources ../knowledge-sources --force

This is a deliberate, manual step rather than an API endpoint or a startup task.
Indexing the CWE catalogue is minutes of CPU and hundreds of megabytes of
memory; something that expensive should happen when a person asks for it, not
when a request arrives.

The script is safe to re-run. A document whose text has not changed since the
last build is skipped, so a rebuild after a catalogue update costs only what
actually moved. ``--force`` re-embeds everything, which is what you want after
changing the chunk size.

Before any of that, it reports what it is about to do and where the sources came
from, because a knowledge base built from the wrong files is indistinguishable
from a correct one until it gives bad advice.
"""

import argparse
import sys
import time
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.core.config import get_settings  # noqa: E402
from app.core.database import SessionLocal  # noqa: E402
from app.knowledge.builder import KnowledgeBuilder  # noqa: E402
from app.knowledge.chunking import SourceDocument  # noqa: E402
from app.knowledge.embedder import EmbeddingBackendUnavailableError, build_embedder  # noqa: E402
from app.knowledge.sources import cwe, notes, owasp  # noqa: E402


def collect(source_dir: Path, *, skip_cwe: bool, skip_owasp: bool) -> list[SourceDocument]:
    documents: list[SourceDocument] = []

    rule_notes = notes.build_documents()
    print(f"  SentinelForge rule notes : {len(rule_notes):>5}")
    documents.extend(rule_notes)

    if not skip_cwe:
        version, weaknesses = cwe.build_documents(source_dir)
        print(
            f"  MITRE CWE catalogue      : {len(weaknesses):>5}  (version {version or 'unknown'})"
        )
        documents.extend(weaknesses)

    if not skip_owasp:
        categories = owasp.build_documents(source_dir / "owasp")
        print(f"  OWASP Top 10 (2021)      : {len(categories):>5}")
        documents.extend(categories)

    return documents


def main() -> int:
    settings = get_settings()
    parser = argparse.ArgumentParser(description="Build the SentinelForge security knowledge base.")
    parser.add_argument(
        "--sources",
        type=Path,
        default=Path(settings.KNOWLEDGE_SOURCE_DIR),
        help="Directory holding cwec_*.xml.zip and owasp/*.md",
    )
    parser.add_argument(
        "--force", action="store_true", help="Re-embed every document, even unchanged ones"
    )
    parser.add_argument("--skip-cwe", action="store_true", help="Skip the CWE catalogue")
    parser.add_argument("--skip-owasp", action="store_true", help="Skip the OWASP Top 10")
    arguments = parser.parse_args()

    source_dir: Path = arguments.sources.expanduser().resolve()
    print(f"Sources : {source_dir}")
    print(
        f"Model   : {settings.KNOWLEDGE_EMBEDDING_MODEL} "
        f"({settings.KNOWLEDGE_EMBEDDING_DIMENSIONS} dimensions)"
    )
    print("Reading sources...")

    try:
        documents = collect(
            source_dir, skip_cwe=arguments.skip_cwe, skip_owasp=arguments.skip_owasp
        )
    except (cwe.CweSourceError, owasp.OwaspSourceError) as error:
        print(f"\nCould not read the sources:\n  {error}", file=sys.stderr)
        return 2

    print(f"\n{len(documents)} documents to consider. Embedding...")
    embedder = build_embedder(settings)
    started = time.monotonic()
    last_report = 0.0

    def progress(done: int, total: int) -> None:
        nonlocal last_report
        now = time.monotonic()
        # Printed on a timer rather than per document: a line per CWE is
        # thousands of lines of noise, and a progress bar that scrolls the
        # errors off the screen is worse than none.
        if now - last_report < 2.0 and done != total:
            return
        last_report = now
        print(f"  {done}/{total} documents ({now - started:.0f}s)", flush=True)

    session = SessionLocal()
    try:
        builder = KnowledgeBuilder(
            session, embedder, max_chunk_chars=settings.KNOWLEDGE_MAX_CHUNK_CHARS
        )
        report = builder.build(documents, force=arguments.force, progress=progress)
    except EmbeddingBackendUnavailableError as error:
        print(f"\n{error}", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        session.rollback()
        # Committed batches stay. Re-running finishes the job.
        print("\nInterrupted. Documents already committed are kept; re-run to continue.")
        return 130
    finally:
        session.close()

    print(f"\nDone in {time.monotonic() - started:.0f}s: {report.summary()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
