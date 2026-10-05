# Detection results: OWASP Benchmark for Python

| | |
| --- | --- |
| Benchmark | OWASP Benchmark for Python, version 0.1 |
| Benchmark commit | `f1291485808b66e20ddb6b01b10dc71b3df8c8ba` |
| Answer key (SHA-256) | `6396f37c97cfd0c018db3d8750095ce6c678a083f83620cfb3e88fe27a46bb0c` |
| Test cases marked | 1230 (the whole benchmark) |
| Vulnerable / safe | 452 / 778 |
| Analyser | SentinelForge 0.1.0 |
| Analyser source (SHA-256) | `4fb2833cd20d28f39326cb758b4c25296cd44669fb59352de6ef266f43c280c7` |
| Parsed with | Python 3.13 |
| Files analysed | 2535 |
| Outcomes (SHA-256) | `23d2c4ae676b0a6fc43e4f9513419692cf40960976eb072136614dbf765dd82d` |

## By category

Recall is the share of vulnerable test cases that were reported. The false positive rate is the share of safe ones that were reported anyway. **Score** is the first minus the second, in percentage points: +100 is perfect, 0 is what reporting everything, reporting nothing or tossing a coin all score. The interval is the 95 % interval of the score.

| Category | CWE | Cases | TP | FN | FP | TN | Recall | False positive rate | Precision | F1 | Score | 95 % interval | Reading |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| cmdi | 78 | 20 | 7 | 6 | 7 | 0 | 53.8 % | 100.0 % | 50.0 % | 51.9 % | -46.2 | -70.9 to -3.9 | worse than guessing |
| codeinj | 94 | 53 | 20 | 0 | 33 | 0 | 100.0 % | 100.0 % | 37.7 % | 54.8 % | 0.0 | -16.1 to +10.4 | not distinguishable from guessing |
| deserialization | 502 | 54 | 18 | 0 | 12 | 24 | 100.0 % | 33.3 % | 60.0 % | 75.0 % | +66.7 | +42.7 to +79.8 | better than guessing |
| hash | 328 | 151 | 71 | 0 | 0 | 80 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +93.1 to +100.0 | better than guessing |
| ldapi | 90 | 29 | 0 | 16 | 0 | 13 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -22.8 to +19.4 | no rule |
| pathtraver | 22 | 168 | 0 | 65 | 0 | 103 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -3.6 to +5.6 | no rule |
| redirect | 601 | 34 | 0 | 13 | 0 | 21 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -15.5 to +22.8 | no rule |
| securecookie | 614 | 39 | 0 | 24 | 0 | 15 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -20.4 to +13.8 | no rule |
| sqli | 89 | 16 | 0 | 5 | 0 | 11 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -25.9 to +43.4 | not distinguishable from guessing |
| trustbound | 501 | 37 | 0 | 18 | 0 | 19 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -16.8 to +17.6 | no rule |
| weakrand | 330 | 326 | 0 | 99 | 0 | 227 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -1.7 to +3.7 | not distinguishable from guessing |
| xpathi | 643 | 186 | 0 | 51 | 0 | 135 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -2.8 to +7.0 | no rule |
| xss | 79 | 89 | 0 | 31 | 0 | 58 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -6.2 to +11.0 | no rule |
| xxe | 611 | 28 | 0 | 8 | 0 | 20 | 0.0 % | 0.0 % | – | 0.0 % | 0.0 | -16.1 to +32.4 | not distinguishable from guessing |
| **All test cases** |  | 1230 | 116 | 336 | 52 | 726 | 25.7 % | 6.7 % | 69.0 % | 37.4 % | +19.0 | +14.7 to +23.5 |  |

## Overall

| | Categories | Recall | False positive rate | Score |
| --- | ---: | ---: | ---: | ---: |
| Average over every category | 14 | 25.3 % | 16.7 % | +8.6 |
| Average over categories the analyser has a rule for | 7 | 50.5 % | 33.3 % | +17.2 |

The first row is the benchmark's own headline figure: each category counts once, including those the analyser has no rule for, which score zero. The second row leaves those out. It describes how good the existing rules are, not how much of the benchmark they cover, and is not a substitute for the first.

## Rules

| Category | Rules that answer it |
| --- | --- |
| cmdi | PY002, PY003 |
| codeinj | PY001 |
| deserialization | PY004, PY005 |
| hash | PY007 |
| ldapi | none: every vulnerable case is missed |
| pathtraver | none: every vulnerable case is missed |
| redirect | none: every vulnerable case is missed |
| securecookie | none: every vulnerable case is missed |
| sqli | PY010 |
| trustbound | none: every vulnerable case is missed |
| weakrand | PY011 |
| xpathi | none: every vulnerable case is missed |
| xss | none: every vulnerable case is missed |
| xxe | PY015 |

## Findings that were not scored

A finding in a test case's file that is of a different kind from the test's question. The answer key says nothing about whether these are real, so they are counted here and are in no figure above.

| Rule | Findings |
| --- | ---: |
| PY015 | 57 |

Findings in files that are not test cases: 1.
