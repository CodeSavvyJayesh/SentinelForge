# Phase 7 — Security knowledge base (RAG): report

**Goal:** give every finding real, citable reference material, retrieved locally
— so that Phase 8's model reasons *about a source* rather than from memory.

**Scope rule followed:** no LLM. Nothing in this phase generates text. It
retrieves text other people wrote, and text we wrote and signed.

---

## 1. Summary

| | |
| --- | --- |
| Backend | 11 files added, 8 changed |
| Database | 1 migration (`9f6e26e043f7`): `knowledge_documents`, `knowledge_chunks` |
| Endpoints | reference material for one finding; knowledge-base status |
| Backend tests | 86 new (478 total) |
| Frontend | a knowledge panel on each finding; 4 new tests (63 total) |
| New dependency | `fastembed` — **optional**, in its own requirements file |
| Docs | this report, `docs/security/knowledge.md`, README, `.env.example` |

---

## 2. Why this comes before the LLM

A model asked "how do I fix this?" with nothing in front of it will answer.
Fluently, plausibly, and without a source. For a security tool that is the
worst possible failure mode, because the output looks exactly like the output
that is right.

So the knowledge comes first, and Phase 8 gets to read rather than recall. The
three sources:

- **MITRE's CWE catalogue** — the standard description of each weakness, its
  consequences and its mitigations. Downloaded, parsed, versioned.
- **The OWASP Top 10 (2021)** — category-level framing.
- **This project's own remediation notes** — one per analyser rule, written in
  the language that rule fires on, naming the call to change. Labelled
  `SentinelForge note` everywhere they appear, because they are ours.

That last one exists because a CWE entry is deliberately language-neutral.
"Use a strong cryptographic hash" is correct and tells nobody which argument to
edit; `MessageDigest.getInstance("SHA-256")` does.

---

## 3. Retrieval: filter first, then rank

This is the design decision of the phase.

```
candidates = chunks WHERE rule_id = ? OR cwe_id = ? OR owasp_category = ?
ranked     = sort(candidates by cosine(query, chunk))
if len(ranked) < limit:  top up from the whole corpus, above a score floor
```

A finding already carries facts the analyser was **certain** about: which rule
fired, and which CWE it maps to. Those are not guesses, so they filter. The
embedding model's job is then only to *order* what survives — within CWE-89, is
this question better answered by the description or by the mitigations?

Unrestricted vector search runs only when the filter comes up short (a rule
with no CWE), and those results must clear `KNOWLEDGE_MIN_SIMILARITY` to appear
at all. A passage returned because it was the least-bad match is noise with a
citation attached.

There is a test for exactly this: a decoy document is planted whose text is a
*better* semantic match than the correct entry, and it still comes second.

This also makes the phase cheap. The common query touches a few dozen vectors.

---

## 4. No vector database

Vectors are 384 little-endian float32 bytes in a PostgreSQL column, normalised
to unit length at index time — so cosine similarity *is* the dot product, and
the square roots are paid once at build time instead of on every comparison.
Similarity is computed in Python, exactly, over every candidate.

**Why not pgvector:** it is a PostgreSQL extension, which means a prebuilt
binary matching the exact server version or a compiler, on every machine this
project is ever run on. At a few thousand passages its index buys nothing
measurable.

**Why not ChromaDB:** a second datastore beside PostgreSQL, with its own files
to back up and its own opportunity to disagree with the findings table.

**Why not numpy:** it would be one more dependency for a dot product that pure
Python does in a few milliseconds at this size — and the scoring code is the one
place a missing dependency must never quietly change the answer.

What this does *not* give is sub-linear search. At a hundred times the corpus
this becomes an ANN index or pgvector, and that is written down here rather than
pretended away.

---

## 5. Embeddings, and the refusal to guess

`fastembed` runs `BAAI/bge-small-en-v1.5` (384 dimensions, ~130 MB) on the CPU
through ONNX. `sentence-transformers` gives the same vectors and brings ~2.5 GB
of PyTorch to do it.

Three refusals, all tested:

- **No fallback.** If the model cannot load, every call raises. An embedder that
  quietly degraded to random vectors would build a knowledge base that looks
  full, answers every query, and is wrong — with nothing in the UI to say so.
- **A wrong-width vector is refused at write time**, so rows that would decode
  into nonsense never reach the database.
- **A knowledge base built by another model is refused at read time.** Vectors
  from two models live in different spaces; the dot products would still be
  numbers, and every one of them would be meaningless.

Likewise, an unbuilt knowledge base returns **503 with a reason**, not an empty
list. "No passages" reads as a statement about the vulnerability; "nobody has
built the knowledge base" is a statement about the installation, and only one of
those should worry anyone.

---

## 6. Parsing MITRE's XML without failing our own audit

This project ships **PY015**, which flags XML parsers that resolve entities. The
catalogue is a download, so:

1. Exactly one `.xml` member is accepted, and its declared size is checked.
2. **Any `DOCTYPE` declaration is refused outright.** Billion-laughs and XXE both
   need one; refusing the declaration removes the class rather than bounding it.
3. Only then is the XML parsed, with namespaces *stripped* rather than matched —
   the catalogue moved from `cwe-6` to `cwe-7`, and a pinned URI would silently
   yield zero weaknesses after the next such change.
4. An empty result is an error, because a knowledge base that silently contains
   nothing answers every question with "no information".

One control was **deleted** during the mutation pass rather than kept: a
streaming byte counter in the extract loop. `zipfile` stops a member read at its
declared uncompressed size and then verifies the CRC, so that counter could
never fire — a tampered header produces a short read and a checksum failure, not
an over-long one. An unreachable control is worse than no control, because it
reads as protection nobody has tested. It was replaced by a test that tampers
with a real zip header and asserts the archive is refused.

Full reasoning: [docs/security/knowledge.md](../../security/knowledge.md).

---

## 7. What the query does not contain

The text embedded for a finding is built from its metadata — rule title,
message, CWE, OWASP category, and the language inferred from the file extension
("...in Java" retrieves different passages from "..." alone).

It deliberately excludes the **code snippet**. A snippet can contain a
credential, and a credential has no business being turned into a vector, logged,
or echoed back through the API. There is a test asserting the secret never
appears in the query, because this is precisely the kind of thing a later
"improvement" would helpfully add.

---

## 8. Frontend

Expanding a finding now loads what the knowledge base says about it — fetched on
expand, not with the list, because fifty findings would otherwise fire fifty
retrievals nobody reads.

Every passage shows its source badge, its identifier (linked), its section, and
**why it was retrieved**: *written for this rule*, *this weakness*, *this OWASP
category*, or *related*. SentinelForge's own notes get a distinct colour. The
query is printed underneath, so a result can be reproduced and argued with.

---

## 9. Verification

| Check | Result |
| --- | --- |
| `pytest` — 478 tests (86 new) against real PostgreSQL | ✅ pass |
| `ruff check` / `ruff format --check` | ✅ pass |
| `alembic upgrade` → `check` → `downgrade` → `upgrade` | ✅ pass |
| Frontend type-check (strict), ESLint (React Compiler rules), 63 tests | ✅ pass |
| Parsing the **real** MITRE catalogue — 944 weaknesses, version 4.20 | ✅ pass |
| Retrieval quality with the **real** model — 6/6 cases | ✅ pass (after two fixes) |
| `verify.ps1` on Windows — 474 passed, 6 skipped | ✅ pass |

### Do the controls bite?

Thirty-seven controls were broken one at a time and the suite re-run. Thirty-six
failed a test immediately. The thirty-seventh — `ON DELETE CASCADE` — survived
mutation of the *model*, because the test database's schema comes from the
migration; removing the constraint directly in PostgreSQL does fail the test,
which is the claim that matters.

Two survivors in the first pass were real gaps, and both were worth finding:

- The **cascade test** deleted through the session, so SQLAlchemy's own cascade
  tidied up in Python and the database constraint was never exercised. It now
  deletes with a Core statement, which is what a migration or a bulk delete
  would do.
- The **content-hash ordering test** rolled the transaction back before
  asserting, which hid whether the builder had already written the hash. It now
  checks the row *without* rolling back, so writing the hash before the passages
  are stored fails the test — which is the whole point of writing it last.

And one control was deleted rather than tested, as described in §6.

### What the real run found

Both claims that could not be checked from the build environment are now
closed, and closing them cost three defects — which is the argument for
insisting on it rather than shipping on green unit tests.

**Parsing the real catalogue** (CWE 4.20, 944 weaknesses, every CWE the rules
map to present) immediately exposed a bug the fixtures could not: the document
title was prefixed onto a passage *after* the text had been split to the size
limit, so a long CWE name pushed 198 passages past it. Nothing complained,
because an embedder truncates an over-long input rather than refusing it — those
passages would have been indexed with their tails missing. The heading now comes
out of the same budget. The corpus is 976 documents and 4,093 passages.

**The first real retrieval run scored 5/6**, and the failure was worth more than
the five passes. For a Java finding about MD5:

```
+0.898  [cwe ] JS005 — Risk     <- JavaScript advice, first
+0.864  [rule] JV003 — Risk     <- the Java note, second
+0.830  [cwe ] PY007 — Risk     <- Python advice, third
! no remediation section in the top 3
```

Two distinct defects in one result:

1. **Another language's advice outranked the right one**, by three hundredths of
   a point. Small embedding models represent a passage's *topic* well and its
   *qualifiers* poorly, so "in Java" in the query barely moved the score. The
   fix is not to fight the model: which rule the finding came from is a fact we
   already hold, so notes are now restricted to their own rule and ranking is
   tiered by specificity before score.
2. **Three restatements of the problem, no remediation.** The query is built
   from a finding, so it is a description of a problem and embeds closest to
   other descriptions of that problem. Similarity was faithfully returning what
   was asked for, and what was asked for was wrong. One slot is now reserved for
   a section that explains how to fix the weakness.

The second is the more interesting failure, because nothing was broken. Every
component did its job and the answer was still useless to the person reading it.

After both fixes, all six cases lead with the finding's own rule note — risk and
fix — followed by catalogue text, with no cross-language passages at all.

---

## 10. Status

- **COMPLETED:** knowledge schema and migration, CWE/OWASP/rule-note readers,
  section-aware chunking, the embedder layer with its three refusals, vector
  storage and exact similarity, filter-first retrieval, the two endpoints, the
  builder CLI, the retrieval-check script, the UI panel, documentation.
- **REMAINING (yours):** the OWASP Top 10 files, whose English copies live in
  `2021/docs/en` rather than `2021/docs`; rebuild afterwards, which costs
  seconds because the catalogue hashes match and is skipped.
- **Deferred on purpose:** an ANN index or pgvector (documented as the scale-out
  path, not pretended away), re-ranking, retrieval over the user's own code
  (that is a different index with different privacy rules), and any generation
  at all — that is Phase 8.

## 11. Next milestone — Phase 8: local LLM analysis and explanation

- Ollama running a local model, with the retrieved passages as its context
- Explanation of a finding grounded in those passages, with the citations kept
- Strict output handling: the model's text is untrusted input like any other
- A refusal path when the model is unavailable, rather than a silent gap

## 12. Study checklist

1. Why does the retrieval filter on CWE and rule *before* it ranks anything — and what does the decoy test prove?
2. Why is the result ordered by specificity before similarity, and why is that not a workaround for a weak model?
3. The first real run returned three passages that were all correct and all useless. Why, and what fixed it?
4. Why are vectors normalised when they are stored rather than when they are compared?
5. What breaks if a knowledge base is half-embedded by one model and half by another, and how does the code notice?
6. Why does an unbuilt knowledge base return 503 instead of an empty list?
7. Why is a `DOCTYPE` refused outright instead of limiting entity expansion?
8. Why are namespaces stripped from the CWE XML rather than matched?
9. Why is the code snippet deliberately excluded from the retrieval query?
10. Why is the knowledge base built by a script rather than by an endpoint?
11. Why is the content hash written *after* the passages, and what would break if it were written first?
12. One control was deleted during verification rather than tested. Which, and why is deleting it the right answer?
