# Detection results: OWASP Benchmark for Java

| | |
| --- | --- |
| Benchmark | OWASP Benchmark for Java, version 1.2 |
| Benchmark commit | `8b67a88d73b2594570fc21150705283de884620b` |
| Answer key (SHA-256) | `1809f6a690c6cf7dd6685df6ebe2eef8fe3ca93d19a7ca0ce45987ca4f5d78e1` |
| Test cases marked | 1351 (the development half) |
| Vulnerable / safe | 710 / 641 |
| Analyser | SentinelForge 0.1.0 |
| Analyser source (SHA-256) | `79a0731a2106c72462c48b27c7086dc3009682eef2a271440f4d127fafb7e504` |
| Parsed with | Python 3.13 |
| Files analysed | 5668 |
| Outcomes (SHA-256) | `67932925caa7276bfb2d7fddd7bbf6af18f2150e2dea41461f3eeaf935359312` |

## By category

Recall is the share of vulnerable test cases that were reported. The false positive rate is the share of safe ones that were reported anyway. **Score** is the first minus the second, in percentage points: +100 is perfect, 0 is what reporting everything, reporting nothing or tossing a coin all score. The interval is the 95 % interval of the score.

| Category | CWE | Cases | TP | FN | FP | TN | Recall | False positive rate | Precision | F1 | Score | 95 % interval | Reading |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| cmdi | 78 | 119 | 0 | 68 | 0 | 51 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -7.0 to +5.3 | not distinguishable from guessing |
| crypto | 327 | 124 | 70 | 0 | 0 | 54 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +91.6 to +100.0 | better than guessing |
| hash | 328 | 105 | 38 | 16 | 0 | 51 | 70.4 % | 0.0 % | 100.0 % | 82.6 % | +70.4 | +55.4 to +80.9 | better than guessing |
| ldapi | 90 | 35 | 0 | 14 | 0 | 21 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -15.5 to +21.5 | no rule |
| pathtraver | 22 | 124 | 0 | 65 | 0 | 59 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -6.1 to +5.6 | no rule |
| securecookie | 614 | 35 | 19 | 0 | 0 | 16 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +74.4 to +100.0 | better than guessing |
| sqli | 89 | 249 | 112 | 17 | 106 | 14 | 86.8 % | 88.3 % | 51.4 % | 64.6 % | -1.5 | -9.8 to +6.9 | not distinguishable from guessing |
| trustbound | 501 | 57 | 0 | 34 | 0 | 23 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -14.3 to +10.2 | no rule |
| weakrand | 330 | 254 | 116 | 0 | 0 | 138 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +95.8 to +100.0 | better than guessing |
| xpathi | 643 | 22 | 0 | 11 | 0 | 11 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -25.9 to +25.9 | no rule |
| xss | 79 | 227 | 0 | 130 | 0 | 97 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -3.8 to +2.9 | no rule |
| **All test cases** |  | 1351 | 355 | 355 | 106 | 535 | 50.0 % | 16.5 % | 77.0 % | 60.6 % | +33.5 | +28.7 to +38.0 |  |

## Overall

| | Categories | Recall | False positive rate | Score |
| --- | ---: | ---: | ---: | ---: |
| Average over every category | 11 | 41.6 % | 8.0 % | +33.5 |
| Average over categories the analyser has a rule for | 6 | 76.2 % | 14.7 % | +61.5 |

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

Over the same 1351 test cases, this run judged 341 correctly that the earlier run got wrong, and 106 wrongly that the earlier run got right (net +235). Exact McNemar test, two-sided: p = 7.64e-30.
