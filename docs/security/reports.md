# Security of reports

Every earlier phase kept findings inside this application, behind a login,
next to the warnings that explain them. A report is the first thing that
**leaves**. It is a document, opened somewhere else, by someone who was never
shown the interface — and it contains text copied out of a repository somebody
else wrote.

That makes two questions worth answering carefully: what can the text in a
report do to the person who opens it, and what does the report claim on the
project's behalf once nobody is there to qualify it.

## A report is untrusted text in a trusted wrapper

File paths, code snippets, branch names and project names all end up in the
document. A repository can contain a file called
`"><script>alert(1)</script>.py`, and a snippet can contain anything at all.

Each format has its own way of being broken by that, so each renderer has its
own rule:

| Format | How text could become structure | What prevents it |
| --- | --- | --- |
| HTML | a tag, or a quote that ends an attribute | every interpolated value goes through one escape function, numbers included |
| Markdown | a link, a heading, a table cell, a closing code fence | prose has every meaningful character escaped; code is fenced with a delimiter longer than any run of backticks inside it |
| SARIF / JSON | — | serialised by a JSON encoder; there is no template |

The tests do not check that particular strings are escaped. They build a report
in which **every** field a repository or a user controls is the payload, and
assert that the resulting document has the same structure as one built from
harmless text: the same HTML tags in the same order, the same Markdown headings.
Anything the payload managed to add would show up as a difference.

## The HTML report has a second lock

Escaping is one function, and one mistake in one place would undo it. So the
HTML document also declares a Content-Security-Policy:

```
default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'
```

No scripts, no frames, no forms, no network requests of any kind. If markup is
ever injected, it cannot run and it cannot call home. The report loads nothing —
no fonts, no stylesheet, no image — which also means opening it tells nobody
that it was opened.

## The API never renders a report on its own origin

When the API serves the HTML report directly (`download=true`), the response is
an **attachment**, under a policy that starts with `sandbox`. It is saved, not
shown. If a browser displays it anyway, the sandbox gives it a unique origin
with no access to this site's cookies or storage.

The web interface does not use that path at all. It asks for the document
wrapped in JSON and shows it inside `<iframe sandbox="">` — an empty sandbox,
which grants nothing: no scripts, no forms, no same-origin access. Downloads are
written to disk from memory and never navigated to.

## The filename is rebuilt, not cleaned

The download name comes from the repository's name, which is user input, and it
is placed in a `Content-Disposition` header. Rather than strip the dangerous
characters, the name is rebuilt from an allow-list: lowercase letters, digits
and hyphens. Quotes, path separators and line breaks are not removed so much as
never included. A test sets a repository's name to a header-injection attempt
and checks that no extra header appears.

## No model output

A report contains **nothing a language model wrote**: no explanation, no
rationale, no diff.

That is a deliberate omission. In the interface, model text is always shown
with its label, its sources and the notice that it is not a verdict. A forwarded
document loses all of that, and "the report says" carries more weight than "the
model suggested". What the report does include about a proposed fix is the one
thing that was checked — the verdict of the re-scan — and its wording is fixed:
a fix that passed "has not been applied to the code".

Remediation advice in a report comes from this project's own per-rule notes,
which are written by hand and reviewed like code.

## What the report says about itself

Every format ends with the same five statements, as fixed text: that the
analysis does not show reachability, that no findings is not a certificate, that
the score is a policy and not CVSS, that a fix which passed was not applied, and
that credential snippets are redacted. They are in the document, not beside it,
because the document is what gets forwarded.

An incomplete scan — one that stopped at the finding limit — is announced
before the numbers, not after them.

## Secrets

Snippets are redacted by the analyser before a finding is stored, so the report
cannot contain what the database does not. A test scans a repository with a
credential in it and checks that the value is in none of the four formats. At
most the first four characters of a credential are kept, and the report says so.

## Who took a report

Every export is written to the audit log: who, which repository, which format,
which scan it described, and how many open findings it listed. The record holds
counts and ids, never the report.

A report cannot be had for another user's repository (404, the same answer as
for one that does not exist), and a refused request leaves no record that could
confirm the repository is there.

## What this does not defend against

- **The person holding the report.** Once downloaded it is a file. Nothing here
  controls who it is sent to.
- **A Markdown renderer with its own extensions.** The escaping targets
  CommonMark and GitHub's dialect. A renderer that gives meaning to other
  characters could still be surprised.
- **Misreading.** A grade of A means these rules matched nothing. The report
  says so in words, and cannot make anyone read them.
