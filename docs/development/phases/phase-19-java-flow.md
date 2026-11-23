# Phase 19 — Following data through Java

**Status:** complete
**Branch:** `phase-19-java-flow`

Phase 16 gave Python a data-flow walk and left Java on patterns, and its
evaluation said exactly what that cost: Java scored +33.5, SQL injection was
reported in 89 % of the safe test cases, and five categories had no rule at all
because every one of them is the question "does request data reach this call",
which a pattern cannot answer. This phase answers it for Java.

| OWASP Benchmark for Java 1.2, held-out half | Phase 16 | Phase 19 |
| --- | ---: | ---: |
| Score, averaged over categories | +33.5 | **+97.1** |
| Recall, all test cases | 50.9 % | 96.6 % |
| False alarms | 100 | **0** |
| Categories with no rule | 5 | 0 |

The held-out half was measured for the second time, once, after the analyser
was frozen. That, and what the figure does and does not show, is in
[docs/evaluation](../../evaluation/README.md#phase-19-java-data-flow).

## What was built

| Module (`backend/app/analysis/`) | What it is |
| --- | --- |
| `java_syntax.py` | Reads Java into a small syntax tree. Hand-written, no dependency. Anything it does not understand is an opaque node; a method body it cannot read is skipped and marked unread; it raises only its own `SyntaxProblem`. |
| `java_flow.py` | Walks methods and describes each value: request data or not, escaped for which uses, origin known or not, its possible constants, list elements, map entries, bean properties. Follows calls into the same file and, lazily, into other files of the project. |
| `java_analysis.py` | Runs the patterns, then uses the walk to withdraw SQL reports on constants and to add the new findings. |

Six rules, each reporting only when request data is shown to reach the call:

| Rule | Request data reaching | CWE |
| --- | --- | --- |
| JV007 | `Runtime.exec`, `ProcessBuilder` (command, arguments, environment) | 78 |
| JV008 | `new File`, file streams, `Paths.get`, `Files.*` | 22 |
| JV009 | the filter of a directory search | 90 |
| JV010 | an XPath expression | 643 |
| JV011 | the response writer | 79 |
| JV012 | a session attribute's name or value | 501 |

Each has a fix note in the knowledge base, so a model asked for a fix is given
the right advice, and is assigned to its benchmark category by the weakness it
declares, the same way as every earlier rule.

SQL001 changed in two ways. The walk **withdraws** a report when every value
joined into the query is built from literals, and **adds** one at the call
when a query reaches the database without passing a line the pattern reported
(`"{call " + name + "}"`, `String.format`); a query built in one method and run
in another is reported once. Separately, SELECT now counts as SQL only when it
is followed by something shaped like a column list, `UNION SELECT`, or `NEXT
VALUE FOR`.

## The rule that keeps it honest

A new finding needs request data shown to reach the call; anything the walk
does not understand is not request data. A withdrawal needs every value shown
to be constant; anything the walk does not understand is not constant. So a
gap in the walk can cost a finding it might have added, never hide one the
pattern made. A method the walk cannot finish within its budget contributes
nothing either way. Tests pin each half of that.

## What went wrong on the way

- **`(7 * 18) + num` was read as text.** The first version joined every `+`
  chain as a string, so `126 + 106` became `"126106"`, the condition was
  undecided, and both branches counted. Forty-nine false alarms on the
  development half were this one mistake. `+` now adds two numbers and joins
  anything else, left to right, as Java does.
- **Setting one property tainted the whole object.** A weak-randomness test
  case calls `cookie.setPath(request.getRequestURI())` and later prints
  `cookie.getName()`. Treating any argument as stored into the object reported
  254 cross-site-scripting findings in files about something else. A setter's
  value is now kept as that property, and only its own getter returns it.
- **A query was reported twice:** where it was built (by the pattern) and
  where it ran (by the walk). A query value now remembers that it was built by
  a join the pattern reports, and is not reported again where it runs.
- **`Files.copy(upload, target)` was judged by its first argument**, which is
  the uploaded content, not a path. It is now judged by the target.
- **It was three times slower.** On Spring Framework, parsing every Java file
  and walking every method of every file made a scan take three times as long.
  Three changes brought the cost down to about half again (21.5 s to 31.5 s on
  the machine measured): a file is walked only if it
  names a servlet request or a Spring request annotation, or has a SQL report
  to check; only methods that can see the request are starting points; and
  other files are indexed by a regular expression and parsed only when a call
  reaches one of their classes.
- **The stricter SELECT dropped real queries.** `"select next value for " +
  name` is a sequence query, not English. `NEXT VALUE FOR` was added after
  reading Spring's results.
- **The work was lost once.** The cloud workspace it was written in was reset
  before the work was committed. It was rebuilt from the session's own record,
  step by step, and checked to give exactly the same results before
  continuing; it has been committed in small steps since.

## Checked on real code

The Phase 16 analyser and this one were run over WebGoat, Spring Framework,
Django and Juice Shop, and every finding that changed was read. Nine new
WebGoat findings, all genuine lesson vulnerabilities; one withdrawn, a test's
payload joined to a constant. Eleven new findings in one Spring test file of
controllers that echo request parameters, correct by the rule's definition.
Eight Spring and four Django SQL false alarms withdrawn (HTML `<select>` tags
and English). Juice Shop unchanged. Details in the evaluation document.

## Tests

| | |
| --- | --- |
| Reader | 23 tests: tokens, declarations, every kind of statement, generics against shifts, casts against parentheses, opaque constructs, an unreadable method, deep nesting, and 300 damaged files that may raise only the reader's own error |
| Walk | 60 tests: every source, every sink, escaping (and escaping for the wrong use), each constant pattern with its tainted twin, calls within a file, into an inner class, through an interface, through a wrapper in another file, recursion, SQL withdrawal and its limits, the budget, lazy parsing, and the engine end to end |
| SQL pattern | 19 new: HTML, CSS and English SELECT not reported; ten shapes of real query still reported |
| Whole backend suite | 1,874 tests; 1,872 pass. The other two need to resolve a host name, which this build environment cannot do; they failed in the same way before this phase |
| Lint | `ruff check` and `ruff format --check` clean |
| Benchmarks | all six recorded results reproduce (`.\\scripts\\evaluate.ps1`) |

## Not verified

- **Windows.** Run `.\scripts\verify.ps1` and `.\scripts\evaluate.ps1`.
- **Frameworks other than servlets and Spring.** JAX-RS, Struts, Play and
  others contribute no request data the walk recognises.

## Limitations

- Fields are not followed beyond static constants, request-typed fields and
  bean properties set and read in one method.
- Only the request is a source; data from a database or a file is not.
- A static library call given only literals counts as constant, so a query
  joined to `System.getProperty(...)` is withdrawn.
- The 24 held-out misses are weak hashes whose algorithm is named in a
  properties file, which the analyser does not read.
- Kotlin and Scala are still read with patterns only.
