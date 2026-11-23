# Detection results: OWASP Benchmark for Java

| | |
| --- | --- |
| Benchmark | OWASP Benchmark for Java, version 1.2 |
| Benchmark commit | `8b67a88d73b2594570fc21150705283de884620b` |
| Answer key (SHA-256) | `1809f6a690c6cf7dd6685df6ebe2eef8fe3ca93d19a7ca0ce45987ca4f5d78e1` |
| Test cases marked | 1351 (the development half) |
| Vulnerable / safe | 710 / 641 |
| Analyser | SentinelForge 0.1.0 |
| Analyser source (SHA-256) | `6b374566f374063eed2c37ec6efed43a0ffcb473c3d46089051558485c086b79` |
| Parsed with | Python 3.13 |
| Files analysed | 5668 |
| Outcomes (SHA-256) | `910ca7c92db8f3897665bcef14a9692a5cf4fc54df39d5c8d44ead1641ed228d` |

## By category

Recall is the share of vulnerable test cases that were reported. The false positive rate is the share of safe ones that were reported anyway. **Score** is the first minus the second, in percentage points: +100 is perfect, 0 is what reporting everything, reporting nothing or tossing a coin all score. The interval is the 95 % interval of the score.

| Category | CWE | Cases | TP | FN | FP | TN | Recall | False positive rate | Precision | F1 | Score | 95 % interval | Reading |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| cmdi | 78 | 119 | 68 | 0 | 0 | 51 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +91.2 to +100.0 | better than guessing |
| crypto | 327 | 124 | 70 | 0 | 0 | 54 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +91.6 to +100.0 | better than guessing |
| hash | 328 | 105 | 38 | 16 | 0 | 51 | 70.4 % | 0.0 % | 100.0 % | 82.6 % | +70.4 | +55.4 to +80.9 | better than guessing |
| ldapi | 90 | 35 | 14 | 0 | 0 | 21 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +73.5 to +100.0 | better than guessing |
| pathtraver | 22 | 124 | 65 | 0 | 0 | 59 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +91.7 to +100.0 | better than guessing |
| securecookie | 614 | 35 | 19 | 0 | 0 | 16 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +74.4 to +100.0 | better than guessing |
| sqli | 89 | 249 | 129 | 0 | 0 | 120 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +95.8 to +100.0 | better than guessing |
| trustbound | 501 | 57 | 34 | 0 | 0 | 23 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +82.5 to +100.0 | better than guessing |
| weakrand | 330 | 254 | 116 | 0 | 0 | 138 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +95.8 to +100.0 | better than guessing |
| xpathi | 643 | 22 | 11 | 0 | 0 | 11 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +63.4 to +100.0 | better than guessing |
| xss | 79 | 227 | 130 | 0 | 0 | 97 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +95.2 to +100.0 | better than guessing |
| **All test cases** |  | 1351 | 694 | 16 | 0 | 641 | 97.7 % | 0.0 % | 100.0 % | 98.9 % | +97.7 | +96.2 to +98.6 |  |

## Overall

| | Categories | Recall | False positive rate | Score |
| --- | ---: | ---: | ---: | ---: |
| Average over every category | 11 | 97.3 % | 0.0 % | +97.3 |
| Average over categories the analyser has a rule for | 11 | 97.3 % | 0.0 % | +97.3 |

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

Over the same 1351 test cases, this run judged 445 correctly that the earlier run got wrong, and 0 wrongly that the earlier run got right (net +445). Exact McNemar test, two-sided: p = 2.2e-134.
