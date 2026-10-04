# Detection results: OWASP Benchmark for Java

| | |
| --- | --- |
| Benchmark | OWASP Benchmark for Java, version 1.2 |
| Benchmark commit | `8b67a88d73b2594570fc21150705283de884620b` |
| Answer key (SHA-256) | `1809f6a690c6cf7dd6685df6ebe2eef8fe3ca93d19a7ca0ce45987ca4f5d78e1` |
| Test cases marked | 2740 (the whole benchmark) |
| Vulnerable / safe | 1415 / 1325 |
| Analyser | SentinelForge 0.1.0 |
| Analyser source (SHA-256) | `79a0731a2106c72462c48b27c7086dc3009682eef2a271440f4d127fafb7e504` |
| Parsed with | Python 3.13 |
| Files analysed | 5668 |
| Outcomes (SHA-256) | `50a6724643773f6bcabc046f361389caea9070c14b9fcc8c6b5c209a57c0157d` |

## By category

Recall is the share of vulnerable test cases that were reported. The false positive rate is the share of safe ones that were reported anyway. **Score** is the first minus the second, in percentage points: +100 is perfect, 0 is what reporting everything, reporting nothing or tossing a coin all score. The interval is the 95 % interval of the score.

| Category | CWE | Cases | TP | FN | FP | TN | Recall | False positive rate | Precision | F1 | Score | 95 % interval | Reading |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| cmdi | 78 | 251 | 0 | 126 | 0 | 125 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -3.0 to +3.0 | not distinguishable from guessing |
| crypto | 327 | 246 | 130 | 0 | 0 | 116 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +95.7 to +100.0 | better than guessing |
| hash | 328 | 236 | 89 | 40 | 0 | 107 | 69.0 % | 0.0 % | 100.0 % | 81.7 % | +69.0 | +59.9 to +76.3 | better than guessing |
| ldapi | 90 | 59 | 0 | 27 | 0 | 32 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -10.7 to +12.5 | no rule |
| pathtraver | 22 | 268 | 0 | 133 | 0 | 135 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -2.8 to +2.8 | no rule |
| securecookie | 614 | 67 | 36 | 0 | 0 | 31 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +85.4 to +100.0 | better than guessing |
| sqli | 89 | 504 | 241 | 31 | 206 | 26 | 88.6 % | 88.8 % | 53.9 % | 67.0 % | -0.2 | -5.7 to +5.5 | not distinguishable from guessing |
| trustbound | 501 | 126 | 0 | 83 | 0 | 43 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -8.2 to +4.4 | no rule |
| weakrand | 330 | 493 | 218 | 0 | 0 | 275 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +97.8 to +100.0 | better than guessing |
| xpathi | 643 | 35 | 0 | 15 | 0 | 20 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -16.1 to +20.4 | no rule |
| xss | 79 | 455 | 0 | 246 | 0 | 209 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -1.8 to +1.5 | no rule |
| **All test cases** |  | 2740 | 714 | 701 | 206 | 1119 | 50.5 % | 15.5 % | 77.6 % | 61.2 % | +34.9 | +31.6 to +38.1 |  |

## Overall

| | Categories | Recall | False positive rate | Score |
| --- | ---: | ---: | ---: | ---: |
| Average over every category | 11 | 41.6 % | 8.1 % | +33.5 |
| Average over categories the analyser has a rule for | 6 | 76.3 % | 14.8 % | +61.5 |

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

Over the same 2740 test cases, this run judged 686 correctly that the earlier run got wrong, and 206 wrongly that the earlier run got right (net +480). Exact McNemar test, two-sided: p = 6.14e-61.
