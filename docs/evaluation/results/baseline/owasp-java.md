# Detection results: OWASP Benchmark for Java

| | |
| --- | --- |
| Benchmark | OWASP Benchmark for Java, version 1.2 |
| Benchmark commit | `8b67a88d73b2594570fc21150705283de884620b` |
| Answer key (SHA-256) | `1809f6a690c6cf7dd6685df6ebe2eef8fe3ca93d19a7ca0ce45987ca4f5d78e1` |
| Test cases marked | 2740 (the whole benchmark) |
| Vulnerable / safe | 1415 / 1325 |
| Analyser | SentinelForge 0.1.0 |
| Analyser source (SHA-256) | `4fb2833cd20d28f39326cb758b4c25296cd44669fb59352de6ef266f43c280c7` |
| Parsed with | Python 3.13 |
| Files analysed | 5668 |
| Outcomes (SHA-256) | `104415757d51168a2d9dfab5055739d61f2c05ebed25c0b031ea40e0fb3695da` |

## By category

Recall is the share of vulnerable test cases that were reported. The false positive rate is the share of safe ones that were reported anyway. **Score** is the first minus the second, in percentage points: +100 is perfect, 0 is what reporting everything, reporting nothing or tossing a coin all score. The interval is the 95 % interval of the score.

| Category | CWE | Cases | TP | FN | FP | TN | Recall | False positive rate | Precision | F1 | Score | 95 % interval | Reading |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| cmdi | 78 | 251 | 0 | 126 | 0 | 125 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -3.0 to +3.0 | not distinguishable from guessing |
| crypto | 327 | 246 | 0 | 130 | 0 | 116 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -3.2 to +2.9 | no rule |
| hash | 328 | 236 | 28 | 101 | 0 | 107 | 21.7 % | 0.0 % | 100.0 % | 35.7 % | +21.7 | +14.6 to +29.6 | better than guessing |
| ldapi | 90 | 59 | 0 | 27 | 0 | 32 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -10.7 to +12.5 | no rule |
| pathtraver | 22 | 268 | 0 | 133 | 0 | 135 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -2.8 to +2.8 | no rule |
| securecookie | 614 | 67 | 0 | 36 | 0 | 31 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -11.0 to +9.6 | no rule |
| sqli | 89 | 504 | 0 | 272 | 0 | 232 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -1.6 to +1.4 | not distinguishable from guessing |
| trustbound | 501 | 126 | 0 | 83 | 0 | 43 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -8.2 to +4.4 | no rule |
| weakrand | 330 | 493 | 0 | 218 | 0 | 275 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -1.4 to +1.7 | no rule |
| xpathi | 643 | 35 | 0 | 15 | 0 | 20 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -16.1 to +20.4 | no rule |
| xss | 79 | 455 | 0 | 246 | 0 | 209 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -1.8 to +1.5 | no rule |
| **All test cases** |  | 2740 | 28 | 1387 | 0 | 1325 | 2.0 % | 0.0 % | 100.0 % | 3.9 % | +2.0 | +1.3 to +2.8 |  |

## Overall

| | Categories | Recall | False positive rate | Score |
| --- | ---: | ---: | ---: | ---: |
| Average over every category | 11 | 2.0 % | 0.0 % | +2.0 |
| Average over categories the analyser has a rule for | 3 | 7.2 % | 0.0 % | +7.2 |

The first row is the benchmark's own headline figure: each category counts once, including those the analyser has no rule for, which score zero. The second row leaves those out. It describes how good the existing rules are, not how much of the benchmark they cover, and is not a substitute for the first.

## Rules

| Category | Rules that answer it |
| --- | --- |
| cmdi | JV001 |
| crypto | none: every vulnerable case is missed |
| hash | JV003 |
| ldapi | none: every vulnerable case is missed |
| pathtraver | none: every vulnerable case is missed |
| securecookie | none: every vulnerable case is missed |
| sqli | SQL001 |
| trustbound | none: every vulnerable case is missed |
| weakrand | none: every vulnerable case is missed |
| xpathi | none: every vulnerable case is missed |
| xss | none: every vulnerable case is missed |

## Findings that were not scored

No finding in a test case's file was of a different kind from its question.

Findings in files that are not test cases: 4.
