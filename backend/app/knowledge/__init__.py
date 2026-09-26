"""The security knowledge base: reference material, indexed for retrieval.

Phase 8 puts a local language model behind every finding. A model asked to
explain a vulnerability with no reference material in front of it will produce
fluent, plausible, unsourced advice — which is exactly the failure mode this
project is not allowed to have. So the knowledge comes first: real text from
MITRE's CWE catalogue and the OWASP Top 10, plus this project's own per-rule
remediation notes, chunked, embedded locally, and retrieved by the rule and CWE
the analyser already recorded.

Nothing in this package calls a network service at query time. The model runs on
the CPU in this process, and the passages come out of the project's own
PostgreSQL database.
"""
