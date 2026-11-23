# Detection results: OWASP Benchmark for Java

| | |
| --- | --- |
| Benchmark | OWASP Benchmark for Java, version 1.2 |
| Benchmark commit | `8b67a88d73b2594570fc21150705283de884620b` |
| Answer key (SHA-256) | `1809f6a690c6cf7dd6685df6ebe2eef8fe3ca93d19a7ca0ce45987ca4f5d78e1` |
| Test cases marked | 2740 (the whole benchmark) |
| Vulnerable / safe | 1415 / 1325 |
| Analyser | SentinelForge 0.1.0 |
| Analyser source (SHA-256) | `6b374566f374063eed2c37ec6efed43a0ffcb473c3d46089051558485c086b79` |
| Parsed with | Python 3.13 |
| Files analysed | 5668 |
| Outcomes (SHA-256) | `81c4f54bf928fef8af0f71fd36c4c6cb2e56493c00aeb0f6117c84eca9f8c251` |

## By category

Recall is the share of vulnerable test cases that were reported. The false positive rate is the share of safe ones that were reported anyway. **Score** is the first minus the second, in percentage points: +100 is perfect, 0 is what reporting everything, reporting nothing or tossing a coin all score. The interval is the 95 % interval of the score.

| Category | CWE | Cases | TP | FN | FP | TN | Recall | False positive rate | Precision | F1 | Score | 95 % interval | Reading |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| cmdi | 78 | 251 | 126 | 0 | 0 | 125 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +95.8 to +100.0 | better than guessing |
| crypto | 327 | 246 | 130 | 0 | 0 | 116 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +95.7 to +100.0 | better than guessing |
| hash | 328 | 236 | 89 | 40 | 0 | 107 | 69.0 % | 0.0 % | 100.0 % | 81.7 % | +69.0 | +59.9 to +76.3 | better than guessing |
| ldapi | 90 | 59 | 27 | 0 | 0 | 32 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +83.6 to +100.0 | better than guessing |
| pathtraver | 22 | 268 | 133 | 0 | 0 | 135 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +96.1 to +100.0 | better than guessing |
| securecookie | 614 | 67 | 36 | 0 | 0 | 31 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +85.4 to +100.0 | better than guessing |
| sqli | 89 | 504 | 272 | 0 | 0 | 232 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +97.9 to +100.0 | better than guessing |
| trustbound | 501 | 126 | 83 | 0 | 0 | 43 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +90.7 to +100.0 | better than guessing |
| weakrand | 330 | 493 | 218 | 0 | 0 | 275 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +97.8 to +100.0 | better than guessing |
| xpathi | 643 | 35 | 15 | 0 | 0 | 20 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +74.0 to +100.0 | better than guessing |
| xss | 79 | 455 | 246 | 0 | 0 | 209 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +97.6 to +100.0 | better than guessing |
| **All test cases** |  | 2740 | 1375 | 40 | 0 | 1325 | 97.2 % | 0.0 % | 100.0 % | 98.6 % | +97.2 | +96.1 to +97.9 |  |

## Overall

| | Categories | Recall | False positive rate | Score |
| --- | ---: | ---: | ---: | ---: |
| Average over every category | 11 | 97.2 % | 0.0 % | +97.2 |
| Average over categories the analyser has a rule for | 11 | 97.2 % | 0.0 % | +97.2 |

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

Over the same 2740 test cases, this run judged 867 correctly that the earlier run got wrong, and 0 wrongly that the earlier run got right (net +867). Exact McNemar test, two-sided: p = 2.03e-261.
