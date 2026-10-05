# Detection results: OWASP Benchmark for Python

| | |
| --- | --- |
| Benchmark | OWASP Benchmark for Python, version 0.1 |
| Benchmark commit | `f1291485808b66e20ddb6b01b10dc71b3df8c8ba` |
| Answer key (SHA-256) | `6396f37c97cfd0c018db3d8750095ce6c678a083f83620cfb3e88fe27a46bb0c` |
| Test cases marked | 622 (the held-out half) |
| Vulnerable / safe | 220 / 402 |
| Analyser | SentinelForge 0.1.0 |
| Analyser source (SHA-256) | `79a0731a2106c72462c48b27c7086dc3009682eef2a271440f4d127fafb7e504` |
| Parsed with | Python 3.13 |
| Files analysed | 2535 |
| Outcomes (SHA-256) | `a55fdaa2b87d74c50fcc7e68a7907591a58425c24a0c73e6179df9ba1813fd35` |

## By category

Recall is the share of vulnerable test cases that were reported. The false positive rate is the share of safe ones that were reported anyway. **Score** is the first minus the second, in percentage points: +100 is perfect, 0 is what reporting everything, reporting nothing or tossing a coin all score. The interval is the 95 % interval of the score.

| Category | CWE | Cases | TP | FN | FP | TN | Recall | False positive rate | Precision | F1 | Score | 95 % interval | Reading |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| cmdi | 78 | 10 | 4 | 2 | 1 | 3 | 66.7 % | 25.0 % | 80.0 % | 72.7 % | +41.7 | -16.3 to +72.9 | not distinguishable from guessing |
| codeinj | 94 | 27 | 10 | 0 | 0 | 17 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +66.7 to +100.0 | better than guessing |
| deserialization | 502 | 27 | 8 | 0 | 2 | 17 | 100.0 % | 10.5 % | 80.0 % | 88.9 % | +89.5 | +50.9 to +97.1 | better than guessing |
| hash | 328 | 72 | 28 | 0 | 0 | 44 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +85.5 to +100.0 | better than guessing |
| ldapi | 90 | 16 | 7 | 1 | 0 | 8 | 87.5 % | 0.0 % | 100.0 % | 93.3 % | +87.5 | +40.1 to +97.8 | better than guessing |
| pathtraver | 22 | 69 | 28 | 2 | 0 | 39 | 93.3 % | 0.0 % | 100.0 % | 96.6 % | +93.3 | +76.2 to +98.2 | better than guessing |
| redirect | 601 | 19 | 7 | 0 | 0 | 12 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +57.1 to +100.0 | better than guessing |
| securecookie | 614 | 18 | 12 | 0 | 0 | 6 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +54.0 to +100.0 | better than guessing |
| sqli | 89 | 12 | 4 | 0 | 0 | 8 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +41.2 to +100.0 | better than guessing |
| trustbound | 501 | 20 | 6 | 5 | 0 | 9 | 54.5 % | 0.0 % | 100.0 % | 70.6 % | +54.5 | +14.6 to +78.7 | better than guessing |
| weakrand | 330 | 176 | 49 | 0 | 0 | 127 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +92.2 to +100.0 | better than guessing |
| xpathi | 643 | 95 | 20 | 6 | 0 | 69 | 76.9 % | 0.0 % | 100.0 % | 87.0 % | +76.9 | +57.2 to +89.0 | better than guessing |
| xss | 79 | 44 | 16 | 2 | 0 | 26 | 88.9 % | 0.0 % | 100.0 % | 94.1 % | +88.9 | +63.7 to +96.9 | better than guessing |
| xxe | 611 | 17 | 3 | 0 | 0 | 14 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +39.9 to +100.0 | better than guessing |
| **All test cases** |  | 622 | 202 | 18 | 3 | 399 | 91.8 % | 0.7 % | 98.5 % | 95.1 % | +91.1 | +86.5 to +94.1 |  |

## Overall

| | Categories | Recall | False positive rate | Score |
| --- | ---: | ---: | ---: | ---: |
| Average over every category | 14 | 90.6 % | 2.5 % | +88.0 |
| Average over categories the analyser has a rule for | 14 | 90.6 % | 2.5 % | +88.0 |

The first row is the benchmark's own headline figure: each category counts once, including those the analyser has no rule for, which score zero. The second row leaves those out. It describes how good the existing rules are, not how much of the benchmark they cover, and is not a substitute for the first.

## Rules

| Category | Rules that answer it |
| --- | --- |
| cmdi | PY002, PY003, PY016 |
| codeinj | PY001 |
| deserialization | PY004, PY005 |
| hash | PY007 |
| ldapi | PY019 |
| pathtraver | PY017 |
| redirect | PY020 |
| securecookie | PY023 |
| sqli | PY010 |
| trustbound | PY022 |
| weakrand | PY011 |
| xpathi | PY018 |
| xss | PY021 |
| xxe | PY015 |

## Findings that were not scored

A finding in a test case's file that is of a different kind from the test's question. The answer key says nothing about whether these are real, so they are counted here and are in no figure above.

| Rule | Findings |
| --- | ---: |
| PY015 | 27 |
| PY021 | 13 |

Findings in files that are not test cases: 1.

## Compared with the earlier run

Over the same 622 test cases, this run judged 178 correctly that the earlier run got wrong, and 0 wrongly that the earlier run got right (net +178). Exact McNemar test, two-sided: p = 5.22e-54.
