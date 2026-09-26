# Security of the knowledge base

The knowledge base is the first part of SentinelForge that reads a file this
project did not produce and was not uploaded by a user: MITRE's CWE catalogue
arrives as a zipped XML download. That is a supply chain, and it is treated as
one.

## Parsing the catalogue

SentinelForge ships a rule — **PY015** — that flags XML parsers which resolve
entities. A builder that parsed a hostile catalogue with an entity-resolving
parser would be this project failing its own audit, and "but MITRE published it"
is not a control: a download can be intercepted, a mirror can be wrong, and a
file on disk can be replaced.

So, in order:

1. **The archive member is read by name, with limits.** Exactly one `.xml`
   member is accepted — several would mean guessing which is the catalogue. Its
   declared size is checked against `MAX_CATALOGUE_BYTES`, *and* the extracted
   stream is counted as it is read, because the zip header is a claim rather
   than a fact. This is the same reasoning as [archive ingestion](ingestion.md).
2. **A `DOCTYPE` declaration is refused outright.** Entity-expansion attacks
   (billion laughs) and external-entity attacks (XXE) both require a DOCTYPE.
   Refusing the declaration removes the whole class, rather than trying to bound
   how deeply an entity may nest or reason about what a URL points at. The
   genuine catalogue has no DOCTYPE, so this costs nothing.
3. **Only then is the XML parsed**, and namespaces are stripped rather than
   matched — the catalogue's namespace moved from `cwe-6` to `cwe-7`, and a
   parser pinned to a URI would silently find zero weaknesses after the next
   such change.
4. **An empty result is an error.** A knowledge base that silently contains
   nothing answers every question with "no information", which reads like a
   verdict about the user's code rather than a fact about the installation.

## What leaves the machine

**At query time: nothing.** The embedding model runs on the CPU in the API
process and the passages come from the project's own PostgreSQL database. No
finding, no snippet and no query is sent anywhere.

**At build time: two downloads, both done by hand.** The CWE catalogue and the
OWASP Top 10 files are fetched by the operator, not by the application, and the
model weights are downloaded once by `fastembed` on first use and cached in
`KNOWLEDGE_MODEL_CACHE_DIR`. After that first run the machine can be offline.

This is stated rather than glossed because "everything is local" is a claim
people make about systems that phone home on startup.

## What the query contains

The text embedded for a finding is built from its **metadata** — rule title,
message, CWE, OWASP category and the language inferred from the file extension.

It deliberately does **not** contain the code snippet. A snippet can contain a
credential, and a credential has no business being turned into a vector, written
to a log line, or echoed back through the API. There is a test asserting this,
because it is the kind of thing a later "improvement" would helpfully add.

## Building is not an endpoint

The knowledge base is built by `scripts/build_knowledge.py`, from files on disk,
by a person at a terminal. There is no HTTP route that triggers it. Two reasons:

- Indexing the catalogue is minutes of CPU and hundreds of megabytes of memory.
  An endpoint that did that on request is a denial of service with an API key.
- An endpoint that accepted documents would let anyone put arbitrary text into
  the advice shown to every user of the installation.

The API's only knowledge routes are reads.

## Retrieval and ownership

The knowledge base itself is not user data — the CWE catalogue is identical for
every account and contains nothing anybody uploaded — so its queries are not
scoped to an owner.

The **finding** is user data, and it is scoped: `GET /findings/{id}/knowledge`
resolves the finding through `FindingRepository.get_for_owner`, which joins
through repositories and projects to `projects.owner_id`. Another user's finding
returns **404, not 403**, for the same reason as everywhere else in this
project: a 403 confirms the id exists.

## Refusing to answer with a broken index

Three states cause retrieval to fail loudly rather than return something:

| State | Why it is refused |
| --- | --- |
| Nothing embedded | An empty list reads as "there is nothing to say about this vulnerability", which is a lie about the vulnerability rather than a fact about the installation. |
| Two embedding models present | Their vectors are in different spaces. The dot products would still be numbers, and every one of them would be meaningless. |
| A model other than the configured one | Same, between stored vectors and the query vector. |

A single unreadable vector is different: it is logged, skipped, and the other
passages are still returned. A corrupt row is a builder problem; losing the
whole explanation of a vulnerability over it would be a worse one.

## Whose advice is shown

SentinelForge's own notes are written per rule and per language. JS005 and
JV003 are the same weakness — a broken hash — in JavaScript and Java, so they
share CWE-327, and a CWE filter alone pulls both in. Handing a Java developer
`crypto.createHash` is worse than handing them nothing, so **a note is only ever
retrieved for the rule it was written for**, on every path including the
unrestricted fallback. The CWE catalogue already carries the language-neutral
form of the same advice, and it is not excluded.

This is enforced in SQL rather than in ranking, because a rule that only holds
"usually" is not a rule.

## Attribution

Every passage carries its source, its identifier, its section and a link.
SentinelForge's own remediation notes are labelled `SentinelForge note` and given
a distinct colour, so they are never mistaken for MITRE's or OWASP's text.
Security advice a developer cannot trace back to who said it is advice they
cannot check.
