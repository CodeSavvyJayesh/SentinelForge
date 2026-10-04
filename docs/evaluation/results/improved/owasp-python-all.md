# Detection results: OWASP Benchmark for Python

| | |
| --- | --- |
| Benchmark | OWASP Benchmark for Python, version 0.1 |
| Benchmark commit | `f1291485808b66e20ddb6b01b10dc71b3df8c8ba` |
| Answer key (SHA-256) | `6396f37c97cfd0c018db3d8750095ce6c678a083f83620cfb3e88fe27a46bb0c` |
| Test cases marked | 1230 (the whole benchmark) |
| Vulnerable / safe | 452 / 778 |
| Analyser | SentinelForge 0.1.0 |
| Analyser source (SHA-256) | `79a0731a2106c72462c48b27c7086dc3009682eef2a271440f4d127fafb7e504` |
| Parsed with | Python 3.13 |
| Files analysed | 2535 |
| Outcomes (SHA-256) | `581f5ee0103cce4350c24b24a85b87920395b28f687296d4184f517fecc472da` |

## By category

Recall is the share of vulnerable test cases that were reported. The false positive rate is the share of safe ones that were reported anyway. **Score** is the first minus the second, in percentage points: +100 is perfect, 0 is what reporting everything, reporting nothing or tossing a coin all score. The interval is the 95 % interval of the score.

| Category | CWE | Cases | TP | FN | FP | TN | Recall | False positive rate | Precision | F1 | Score | 95 % interval | Reading |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| cmdi | 78 | 20 | 11 | 2 | 1 | 6 | 84.6 % | 14.3 % | 91.7 % | 88.0 % | +70.3 | +24.6 to +86.4 | better than guessing |
| codeinj | 94 | 53 | 20 | 0 | 1 | 32 | 100.0 % | 3.0 % | 95.2 % | 97.6 % | +97.0 | +76.7 to +99.5 | better than guessing |
| deserialization | 502 | 54 | 18 | 0 | 2 | 34 | 100.0 % | 5.6 % | 90.0 % | 94.7 % | +94.4 | +72.8 to +98.5 | better than guessing |
| hash | 328 | 151 | 71 | 0 | 0 | 80 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +93.1 to +100.0 | better than guessing |
| ldapi | 90 | 29 | 14 | 2 | 0 | 13 | 87.5 % | 0.0 % | 100.0 % | 93.3 % | +87.5 | +54.7 to +96.5 | better than guessing |
| pathtraver | 22 | 168 | 59 | 6 | 0 | 103 | 90.8 % | 0.0 % | 100.0 % | 95.2 % | +90.8 | +80.6 to +95.7 | better than guessing |
| redirect | 601 | 34 | 13 | 0 | 0 | 21 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +72.4 to +100.0 | better than guessing |
| securecookie | 614 | 39 | 24 | 0 | 0 | 15 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +75.4 to +100.0 | better than guessing |
| sqli | 89 | 16 | 5 | 0 | 0 | 11 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +49.4 to +100.0 | better than guessing |
| trustbound | 501 | 37 | 12 | 6 | 0 | 19 | 66.7 % | 0.0 % | 100.0 % | 80.0 % | +66.7 | +38.2 to +83.7 | better than guessing |
| weakrand | 330 | 326 | 99 | 0 | 0 | 227 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +95.9 to +100.0 | better than guessing |
| xpathi | 643 | 186 | 43 | 8 | 0 | 135 | 84.3 % | 0.0 % | 100.0 % | 91.5 % | +84.3 | +71.7 to +91.8 | better than guessing |
| xss | 79 | 89 | 25 | 6 | 0 | 58 | 80.6 % | 0.0 % | 100.0 % | 89.3 % | +80.6 | +62.6 to +90.8 | better than guessing |
| xxe | 611 | 28 | 8 | 0 | 0 | 20 | 100.0 % | 0.0 % | 100.0 % | 100.0 % | +100.0 | +63.8 to +100.0 | better than guessing |
| **All test cases** |  | 1230 | 422 | 30 | 4 | 774 | 93.4 % | 0.5 % | 99.1 % | 96.1 % | +92.8 | +90.1 to +94.8 |  |

## Overall

| | Categories | Recall | False positive rate | Score |
| --- | ---: | ---: | ---: | ---: |
| Average over every category | 14 | 92.5 % | 1.6 % | +90.8 |
| Average over categories the analyser has a rule for | 14 | 92.5 % | 1.6 % | +90.8 |

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
| PY015 | 57 |
| PY021 | 24 |

Findings in files that are not test cases: 1.

## Compared with the earlier run

Over the same 1230 test cases, this run judged 354 correctly that the earlier run got wrong, and 0 wrongly that the earlier run got right (net +354). Exact McNemar test, two-sided: p = 5.45e-107.
