# Detection results: OWASP Benchmark for Python

| | |
| --- | --- |
| Benchmark | OWASP Benchmark for Python, version 0.1 |
| Benchmark commit | `f1291485808b66e20ddb6b01b10dc71b3df8c8ba` |
| Answer key (SHA-256) | `6396f37c97cfd0c018db3d8750095ce6c678a083f83620cfb3e88fe27a46bb0c` |
| Test cases marked | 608 (the development half) |
| Vulnerable / safe | 232 / 376 |
| Analyser | SentinelForge 0.1.0 |
| Analyser source (SHA-256) | `79a0731a2106c72462c48b27c7086dc3009682eef2a271440f4d127fafb7e504` |
| Parsed with | Python 3.13 |
| Files analysed | 2535 |
| Outcomes (SHA-256) | `b72dbd864bfa41c558a513da56b111f44aa8b82b406d8db878bf3017c34578f8` |

## By category

Recall is the share of vulnerable test cases that were reported. The false positive rate is the share of safe ones that were reported anyway. **Score** is the first minus the second, in percentage points: +100 is perfect, 0 is what reporting everything, reporting nothing or tossing a coin all score. The interval is the 95 % interval of the score.

| Category | CWE | Cases | TP | FN | FP | TN | Recall | False positive rate | Precision | F1 | Score | 95 % interval | Reading |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| cmdi | 78 | 10 | 7 | 0 | 0 | 3 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +33.6 to +100.0 | better than guessing |
| codeinj | 94 | 26 | 10 | 0 | 1 | 15 | 100.0 % | 6.2 % | 90.9 % | 95.2 % | +93.8 | +58.3 to +98.9 | better than guessing |
| deserialization | 502 | 27 | 10 | 0 | 0 | 17 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +66.7 to +100.0 | better than guessing |
| hash | 328 | 79 | 43 | 0 | 0 | 36 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +87.3 to +100.0 | better than guessing |
| ldapi | 90 | 13 | 7 | 1 | 0 | 5 | 87.5 % | 0.0 % | 100.0 % | 93.3 % | +87.5 | +32.0 to +97.8 | better than guessing |
| pathtraver | 22 | 99 | 31 | 4 | 0 | 64 | 88.6 % | 0.0 % | 100.0 % | 93.9 % | +88.6 | +73.0 to +95.5 | better than guessing |
| redirect | 601 | 15 | 6 | 0 | 0 | 9 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +50.8 to +100.0 | better than guessing |
| securecookie | 614 | 21 | 12 | 0 | 0 | 9 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +61.5 to +100.0 | better than guessing |
| sqli | 89 | 4 | 1 | 0 | 0 | 3 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +2.8 to +100.0 | better than guessing |
| trustbound | 501 | 17 | 6 | 1 | 0 | 10 | 85.7 % | 0.0 % | 100.0 % | 92.3 % | +85.7 | +39.4 to +97.4 | better than guessing |
| weakrand | 330 | 150 | 50 | 0 | 0 | 100 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +92.0 to +100.0 | better than guessing |
| xpathi | 643 | 91 | 23 | 2 | 0 | 66 | 92.0 % | 0.0 % | 100.0 % | 95.8 % | +92.0 | +74.2 to +97.8 | better than guessing |
| xss | 79 | 45 | 9 | 4 | 0 | 32 | 69.2 % | 0.0 % | 100.0 % | 81.8 % | +69.2 | +40.3 to +87.3 | better than guessing |
| xxe | 611 | 11 | 5 | 0 | 0 | 6 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +41.6 to +100.0 | better than guessing |
| **All test cases** |  | 608 | 220 | 12 | 1 | 375 | 94.8 % | 0.3 % | 99.5 % | 97.1 % | +94.6 | +90.7 to +96.8 |  |

## Overall

| | Categories | Recall | False positive rate | Score |
| --- | ---: | ---: | ---: | ---: |
| Average over every category | 14 | 94.5 % | 0.4 % | +94.1 |
| Average over categories the analyser has a rule for | 14 | 94.5 % | 0.4 % | +94.1 |

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
| PY015 | 30 |
| PY021 | 11 |

Findings in files that are not test cases: 1.

## Compared with the earlier run

Over the same 608 test cases, this run judged 176 correctly that the earlier run got wrong, and 0 wrongly that the earlier run got right (net +176). Exact McNemar test, two-sided: p = 2.09e-53.
