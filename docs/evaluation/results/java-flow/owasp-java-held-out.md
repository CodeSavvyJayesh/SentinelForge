# Detection results: OWASP Benchmark for Java

| | |
| --- | --- |
| Benchmark | OWASP Benchmark for Java, version 1.2 |
| Benchmark commit | `8b67a88d73b2594570fc21150705283de884620b` |
| Answer key (SHA-256) | `1809f6a690c6cf7dd6685df6ebe2eef8fe3ca93d19a7ca0ce45987ca4f5d78e1` |
| Test cases marked | 1389 (the held-out half) |
| Vulnerable / safe | 705 / 684 |
| Analyser | SentinelForge 0.1.0 |
| Analyser source (SHA-256) | `6b374566f374063eed2c37ec6efed43a0ffcb473c3d46089051558485c086b79` |
| Parsed with | Python 3.13 |
| Files analysed | 5668 |
| Outcomes (SHA-256) | `01c46846f5666e66fa50bcd1d53f2489bea49e44a3d03dd80298aef399518f79` |

## By category

Recall is the share of vulnerable test cases that were reported. The false positive rate is the share of safe ones that were reported anyway. **Score** is the first minus the second, in percentage points: +100 is perfect, 0 is what reporting everything, reporting nothing or tossing a coin all score. The interval is the 95 % interval of the score.

| Category | CWE | Cases | TP | FN | FP | TN | Recall | False positive rate | Precision | F1 | Score | 95 % interval | Reading |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| cmdi | 78 | 132 | 58 | 0 | 0 | 74 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +92.1 to +100.0 | better than guessing |
| crypto | 327 | 122 | 60 | 0 | 0 | 62 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +91.6 to +100.0 | better than guessing |
| hash | 328 | 131 | 51 | 24 | 0 | 56 | 68.0 % | 0.0 % | 100.0 % | 81.0 % | +68.0 | +55.1 to +77.5 | better than guessing |
| ldapi | 90 | 24 | 13 | 0 | 0 | 11 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +65.5 to +100.0 | better than guessing |
| pathtraver | 22 | 144 | 68 | 0 | 0 | 76 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +92.8 to +100.0 | better than guessing |
| securecookie | 614 | 32 | 17 | 0 | 0 | 15 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +72.5 to +100.0 | better than guessing |
| sqli | 89 | 255 | 143 | 0 | 0 | 112 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +95.8 to +100.0 | better than guessing |
| trustbound | 501 | 69 | 49 | 0 | 0 | 20 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +82.3 to +100.0 | better than guessing |
| weakrand | 330 | 239 | 102 | 0 | 0 | 137 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +95.5 to +100.0 | better than guessing |
| xpathi | 643 | 13 | 4 | 0 | 0 | 9 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +42.6 to +100.0 | better than guessing |
| xss | 79 | 228 | 116 | 0 | 0 | 112 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +95.4 to +100.0 | better than guessing |
| **All test cases** |  | 1389 | 681 | 24 | 0 | 684 | 96.6 % | 0.0 % | 100.0 % | 98.3 % | +96.6 | +94.9 to +97.7 |  |

## Overall

| | Categories | Recall | False positive rate | Score |
| --- | ---: | ---: | ---: | ---: |
| Average over every category | 11 | 97.1 % | 0.0 % | +97.1 |
| Average over categories the analyser has a rule for | 11 | 97.1 % | 0.0 % | +97.1 |

The first row is the benchmark's own headline figure: each category counts once, including those the analyser has no rule for, which score zero. The second row leaves those out. It describes how good the existing rules are, not how much of the benchmark they cover, and is not a substitute for the first.

## Rules

| Category | Rules that answer it |
| --- | --- |
| cmdi | JV001, JV007 |
| crypto | JV004 |
| hash | JV003 |
| ldapi | JV009 |
| pathtraver | JV008 |
| securecookie | JV006 |
| sqli | SQL001 |
| trustbound | JV012 |
| weakrand | JV005 |
| xpathi | JV010 |
| xss | JV011 |

## Findings that were not scored

No finding in a test case's file was of a different kind from its question.

Findings in files that are not test cases: 4.

## Compared with the earlier run

Over the same 1389 test cases, this run judged 422 correctly that the earlier run got wrong, and 0 wrongly that the earlier run got right (net +422). Exact McNemar test, two-sided: p = 1.85e-127.
