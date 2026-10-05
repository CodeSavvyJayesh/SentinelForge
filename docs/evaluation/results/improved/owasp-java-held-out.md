# Detection results: OWASP Benchmark for Java

| | |
| --- | --- |
| Benchmark | OWASP Benchmark for Java, version 1.2 |
| Benchmark commit | `8b67a88d73b2594570fc21150705283de884620b` |
| Answer key (SHA-256) | `1809f6a690c6cf7dd6685df6ebe2eef8fe3ca93d19a7ca0ce45987ca4f5d78e1` |
| Test cases marked | 1389 (the held-out half) |
| Vulnerable / safe | 705 / 684 |
| Analyser | SentinelForge 0.1.0 |
| Analyser source (SHA-256) | `79a0731a2106c72462c48b27c7086dc3009682eef2a271440f4d127fafb7e504` |
| Parsed with | Python 3.13 |
| Files analysed | 5668 |
| Outcomes (SHA-256) | `1f5ff2a2e10129d8a3e0500d57660aab95b45cbe8e0594d93cce6ee4eeb206ed` |

## By category

Recall is the share of vulnerable test cases that were reported. The false positive rate is the share of safe ones that were reported anyway. **Score** is the first minus the second, in percentage points: +100 is perfect, 0 is what reporting everything, reporting nothing or tossing a coin all score. The interval is the 95 % interval of the score.

| Category | CWE | Cases | TP | FN | FP | TN | Recall | False positive rate | Precision | F1 | Score | 95 % interval | Reading |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| cmdi | 78 | 132 | 0 | 58 | 0 | 74 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -4.9 to +6.2 | not distinguishable from guessing |
| crypto | 327 | 122 | 60 | 0 | 0 | 62 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +91.6 to +100.0 | better than guessing |
| hash | 328 | 131 | 51 | 24 | 0 | 56 | 68.0 % | 0.0 % | 100.0 % | 81.0 % | +68.0 | +55.1 to +77.5 | better than guessing |
| ldapi | 90 | 24 | 0 | 13 | 0 | 11 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -25.9 to +22.8 | no rule |
| pathtraver | 22 | 144 | 0 | 68 | 0 | 76 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -4.8 to +5.3 | no rule |
| securecookie | 614 | 32 | 17 | 0 | 0 | 15 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +72.5 to +100.0 | better than guessing |
| sqli | 89 | 255 | 129 | 14 | 100 | 12 | 90.2 % | 89.3 % | 56.3 % | 69.4 % | +0.9 | -6.5 to +9.0 | not distinguishable from guessing |
| trustbound | 501 | 69 | 0 | 49 | 0 | 20 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -16.1 to +7.3 | no rule |
| weakrand | 330 | 239 | 102 | 0 | 0 | 137 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +95.5 to +100.0 | better than guessing |
| xpathi | 643 | 13 | 0 | 4 | 0 | 9 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -29.9 to +49.0 | no rule |
| xss | 79 | 228 | 0 | 116 | 0 | 112 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -3.3 to +3.2 | no rule |
| **All test cases** |  | 1389 | 359 | 346 | 100 | 584 | 50.9 % | 14.6 % | 78.2 % | 61.7 % | +36.3 | +31.6 to +40.7 |  |

## Overall

| | Categories | Recall | False positive rate | Score |
| --- | ---: | ---: | ---: | ---: |
| Average over every category | 11 | 41.7 % | 8.1 % | +33.5 |
| Average over categories the analyser has a rule for | 6 | 76.4 % | 14.9 % | +61.5 |

The first row is the benchmark's own headline figure: each category counts once, including those the analyser has no rule for, which score zero. The second row leaves those out. It describes how good the existing rules are, not how much of the benchmark they cover, and is not a substitute for the first.

## Rules

| Category | Rules that answer it |
| --- | --- |
| cmdi | JV001 |
| crypto | JV004 |
| hash | JV003 |
| ldapi | none: every vulnerable case is missed |
| pathtraver | none: every vulnerable case is missed |
| securecookie | JV006 |
| sqli | SQL001 |
| trustbound | none: every vulnerable case is missed |
| weakrand | JV005 |
| xpathi | none: every vulnerable case is missed |
| xss | none: every vulnerable case is missed |

## Findings that were not scored

No finding in a test case's file was of a different kind from its question.

Findings in files that are not test cases: 4.

## Compared with the earlier run

Over the same 1389 test cases, this run judged 345 correctly that the earlier run got wrong, and 100 wrongly that the earlier run got right (net +245). Exact McNemar test, two-sided: p = 1.31e-32.
