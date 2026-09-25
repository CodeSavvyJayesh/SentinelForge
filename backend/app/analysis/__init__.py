"""Static analysis: read the ingested code and say what is wrong with it.

Two hard rules, both inherited from Phase 4 and both load-bearing here:

* **Nothing is executed.** Python is parsed into a syntax tree; everything else
  is matched as text. No import, no build, no test run.
* **Findings are claims, not verdicts.** Every rule carries a confidence as
  well as a severity, and every rule has a test proving it stays quiet on safe
  code. A scanner that cries wolf gets switched off, and a switched-off scanner
  finds nothing at all.
"""
