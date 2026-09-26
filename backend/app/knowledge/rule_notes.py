"""This project's own remediation notes — one per analyser rule.

The CWE catalogue explains a weakness in the abstract: what it is, what it
leads to, and mitigations phrased to cover every language at once. That is the
right level for a standard and the wrong level for a developer looking at line
four of a Java file. "Use a strong cryptographic hash" does not tell anyone
which argument to change.

So each rule gets a note written here, in the language the rule fires on, with
the call to make instead. These are indexed alongside the CWE and OWASP text and
are attributed to ``SENTINELFORGE`` wherever they are shown, because they are
this project's words and must never be mistaken for a standards body's.

Two sections per note, indexed separately:

* **Risk** — what an attacker does with this, concretely.
* **Fix** — what to write instead.

Every rule in ``app.analysis.rules`` must appear here; a test fails if one is
missing, because a rule with no note is a finding the explanation layer has
nothing to say about.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class RuleNote:
    rule_id: str
    title: str
    language: str
    risk: str
    fix: str


def _note(rule_id: str, title: str, language: str, risk: str, fix: str) -> RuleNote:
    return RuleNote(rule_id, title, language, " ".join(risk.split()), " ".join(fix.split()))


RULE_NOTES: tuple[RuleNote, ...] = (
    _note(
        "PY001",
        "eval() or exec() on a value built at runtime",
        "Python",
        """Whatever reaches that string runs as Python, with the privileges of the
        process. A request parameter, a configuration file or a database column is
        enough: an attacker who controls any part of the expression can call
        __import__('os').system(...) and own the host. Sandboxing eval by clearing
        __builtins__ does not work and has been broken repeatedly.""",
        """If the input is data, parse it as data: ast.literal_eval for Python
        literals, json.loads for JSON. If the input selects behaviour, dispatch
        through an explicit dictionary mapping allowed names to functions, so an
        unknown name raises KeyError instead of executing. Reserve eval and exec
        for expressions that are entirely written by you.""",
    ),
    _note(
        "PY002",
        "subprocess called with shell=True",
        "Python",
        """shell=True hands the command to /bin/sh, so shell metacharacters in any
        interpolated value are interpreted rather than passed along. A filename of
        "; rm -rf ~" is a second command. The quoting tricks that look like they fix
        this (wrapping in quotes, stripping semicolons) are routinely bypassed with
        backticks, $(), newlines or unicode.""",
        """Drop shell=True and pass the command as a list:
        subprocess.run(["git", "clone", url], check=True). The arguments then reach
        the program directly and no shell parses them. If you genuinely need a
        pipeline or a redirect, build it with two subprocesses connected by pipes,
        or keep shell=True but with a command string that contains no
        externally-supplied values at all.""",
    ),
    _note(
        "PY003",
        "os.system() or os.popen()",
        "Python",
        """Both run their argument through the shell, so any value concatenated into
        the command is executed as shell syntax. They also give you no way to pass
        arguments safely, no exit-code handling worth the name, and no timeout.""",
        """Use subprocess.run with a list of arguments and check=True:
        subprocess.run(["convert", source, target], check=True, timeout=30). Capture
        output with capture_output=True rather than reading from os.popen.""",
    ),
    _note(
        "PY004",
        "yaml.load() without a safe loader",
        "Python",
        """PyYAML's default loader can construct arbitrary Python objects from tags
        such as !!python/object/apply:os.system. A YAML file is therefore executable
        content, and loading one supplied by a user is equivalent to running it.""",
        """Call yaml.safe_load(stream), or yaml.load(stream, Loader=yaml.SafeLoader).
        SafeLoader builds only standard YAML types — strings, numbers, lists, dicts —
        and refuses the Python-specific tags. If you need custom types, subclass
        SafeLoader and register exactly the constructors you intend to allow.""",
    ),
    _note(
        "PY005",
        "pickle used on data from outside the process",
        "Python",
        """Unpickling is not parsing: the format contains opcodes that call
        importable objects, so a crafted payload runs code during pickle.loads. This
        applies to anything built on pickle, including the default joblib and torch
        load paths and a cache backend configured to pickle.""",
        """Use a data format that cannot execute: json for simple structures, or a
        schema-validated format such as protobuf or msgpack. Validate the decoded
        result against a pydantic model rather than trusting its shape. If pickle is
        unavoidable for trusted internal data, authenticate it first — store an
        HMAC alongside the blob and verify it before loads.""",
    ),
    _note(
        "PY006",
        "Credential assigned in source code",
        "Python",
        """A secret in source is a secret in every clone, every fork, every CI log
        and every backup, and it stays in git history after the line is deleted.
        Anyone with read access to the repository has it, and repository access is
        granted far more freely than production credentials ever are.""",
        """Read it from the environment: os.environ["API_KEY"], or a pydantic
        BaseSettings field so a missing value fails at startup rather than at 3am.
        Keep local values in a .env file that is listed in .gitignore. Then rotate
        the exposed credential — removing the line does not un-leak it, because it
        is still in the commit history and in every existing clone.""",
    ),
    _note(
        "PY007",
        "MD5 or SHA-1 used as a hash",
        "Python",
        """MD5 collisions can be produced in seconds and SHA-1 collisions have been
        demonstrated, so neither can show that two inputs are the same file or that a
        signature is authentic. Both are also fast, which is exactly wrong for
        passwords: a GPU tries billions of candidates per second against them.""",
        """For integrity or fingerprinting, use hashlib.sha256. For passwords, do not
        use a general-purpose hash at all — use hashlib.scrypt or argon2-cffi with a
        per-password salt and a deliberately high cost (this project's own password
        hashing does exactly that). If the hash is genuinely not a security control
        — a cache key, a bucket index — say so in the code with
        hashlib.md5(data, usedforsecurity=False).""",
    ),
    _note(
        "PY008",
        "TLS certificate verification disabled",
        "Python",
        """verify=False keeps the encryption and throws away the identity check, so
        anyone able to intercept the connection can present their own certificate and
        read and rewrite the traffic. The padlock is still there; it now means
        nothing. This usually gets added to silence an error about a self-signed or
        expired certificate, and then ships.""",
        """Leave verify at its default. For an internal CA, point requests at it:
        requests.get(url, verify="/path/to/ca-bundle.pem"), or set REQUESTS_CA_BUNDLE.
        For a self-signed certificate you control, add that certificate to the trust
        store instead of disabling the check. If the certificate is expired, renew
        it — the error is correct.""",
    ),
    _note(
        "PY009",
        "Flask started with debug=True",
        "Python",
        """The debug server exposes the Werkzeug interactive debugger, which offers a
        Python console on any unhandled exception. If the console PIN is disabled,
        guessable, or the attacker can read it from the logs, that console is remote
        code execution. Tracebacks also disclose source, local variables and paths.""",
        """Never enable debug on anything reachable beyond localhost. Drive it from
        configuration — app.run(debug=os.environ.get("FLASK_DEBUG") == "1") — and in
        production run behind a real WSGI server (gunicorn, uwsgi) which does not use
        app.run at all.""",
    ),
    _note(
        "PY010",
        "SQL query built by string formatting",
        "Python",
        """Concatenating or f-stringing a value into SQL lets that value change the
        statement's structure: a quote closes the literal and the rest is parsed as
        SQL. That is how authentication is bypassed with ' OR '1'='1 and how whole
        tables are read through a UNION. Escaping by hand fails on encodings, numeric
        contexts and identifiers.""",
        """Pass values as parameters and let the driver bind them:
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,)) with psycopg,
        or SQLAlchemy's select(User).where(User.email == email). The query text then
        never contains user data. Table and column names cannot be bound — if one
        must vary, check it against an explicit allow-list of known names.""",
    ),
    _note(
        "PY011",
        "random module used for a security value",
        "Python",
        """random is a Mersenne Twister seeded from the clock. It is not
        unpredictable: 624 consecutive outputs are enough to reconstruct its internal
        state and compute every past and future value. A password-reset token or
        session id generated this way can be predicted by anyone who has seen a few
        of them.""",
        """Use the secrets module for anything an attacker must not guess:
        secrets.token_urlsafe(32) for tokens, secrets.token_bytes for keys,
        secrets.choice for picking from a sequence. Keep random for simulations,
        sampling and test data, where predictability is a feature.""",
    ),
    _note(
        "PY012",
        "tempfile.mktemp() is unsafe",
        "Python",
        """mktemp returns a name and then does nothing with it, leaving a window
        between the check and your open in which another process on the same machine
        can create that path — commonly as a symlink to a file you have permission to
        write. Your write then lands somewhere else.""",
        """Use tempfile.NamedTemporaryFile() or tempfile.mkstemp(), which create the
        file atomically with private permissions and hand you an open descriptor, or
        tempfile.TemporaryDirectory() when you need a working directory. There is no
        safe way to use the name mktemp returns.""",
    ),
    _note(
        "PY013",
        "JWT decoded without verifying the signature",
        "Python",
        """A JWT is not secret — it is base64, readable by anyone holding it. The
        signature is the only thing that makes its claims trustworthy. Decoding with
        verification off means anyone can edit the payload, set "role": "admin", and
        be believed. Accepting the token's own "alg" header is the same failure: an
        attacker sets alg to none, or to HS256 against your RSA public key.""",
        """Verify every token you act on, and pin the algorithm yourself:
        jwt.decode(token, key, algorithms=["HS256"]). Never pass
        options={"verify_signature": False} outside a debugging script, and never
        read the algorithm from the token. Check exp, and check aud and iss if you
        issue tokens for more than one audience.""",
    ),
    _note(
        "PY014",
        "Unverified SSL context created",
        "Python",
        """ssl._create_unverified_context() returns a context that accepts any
        certificate from any host — no chain validation, no hostname check. Any
        connection using it can be intercepted transparently. The leading underscore
        is the standard library saying this is not for production use.""",
        """Use ssl.create_default_context(), which verifies the chain and the
        hostname. Load a private CA with context.load_verify_locations(cafile=...)
        rather than turning verification off, and leave check_hostname True.""",
    ),
    _note(
        "PY015",
        "XML parsed with a parser that resolves entities",
        "Python",
        """An XML document can declare entities that expand into other entities; ten
        levels of that turns a few hundred bytes into gigabytes of memory, which is
        the billion-laughs denial of service. A document can also declare an external
        entity pointing at file:///etc/passwd or at an internal URL, and a parser that
        resolves it will read that file or make that request on your behalf.""",
        """Parse untrusted XML with defusedxml — defusedxml.ElementTree.parse is a
        drop-in replacement that refuses entity declarations and external references.
        If adding a dependency is not possible, reject any document containing a
        DOCTYPE declaration before parsing it, which is what this project's own
        knowledge-base builder does.""",
    ),
    _note(
        "JS001",
        "eval() on a value built at runtime",
        "JavaScript",
        """eval runs its argument as JavaScript in the current scope, so any
        attacker-controlled fragment becomes code with access to your variables,
        cookies and DOM. new Function, setTimeout with a string argument, and
        indirect eval all have the same effect.""",
        """Parse data with JSON.parse. Select behaviour through an object literal used
        as a lookup table, so an unrecognised key is undefined rather than executable.
        For arithmetic supplied by a user, use a small expression parser rather than
        handing the string to the engine.""",
    ),
    _note(
        "JS002",
        "child_process.exec() with an interpolated command",
        "JavaScript",
        """exec spawns a shell, so a value containing ;, |, && or $() runs extra
        commands with the privileges of the Node process. Template literals make this
        easy to write and easy to miss in review.""",
        """Use execFile or spawn with an argument array:
        execFile("git", ["clone", url], callback). No shell is involved, so
        metacharacters are just characters. If you must use exec, the command string
        may not contain any value that came from outside the program.""",
    ),
    _note(
        "JS003",
        "HTML assigned from a variable",
        "JavaScript",
        """Assigning to innerHTML parses the string as HTML, so a value containing
        <img src=x onerror=...> executes script in the page's origin — reading
        cookies, calling your API as the signed-in user, or rewriting the page.
        Stripping <script> tags does not help; there are dozens of other ways in.""",
        """If the value is text, assign it to textContent — it is never parsed as
        markup, and it is also faster. If the value really is HTML from a rich-text
        editor, sanitise it with a maintained library such as DOMPurify before it
        touches the DOM. In React, avoid dangerouslySetInnerHTML unless the content
        has been through a sanitiser first.""",
    ),
    _note(
        "JS004",
        "Math.random() used for a security value",
        "JavaScript",
        """Math.random is a fast non-cryptographic generator with no guarantee of
        unpredictability, and in V8 its internal state can be recovered from a short
        run of outputs. Tokens, session ids, password-reset links and OTPs built on it
        are guessable.""",
        """In the browser use crypto.getRandomValues(new Uint8Array(32)), or
        crypto.randomUUID() for an identifier. In Node use
        crypto.randomBytes(32).toString("hex"), or crypto.randomUUID(). Keep
        Math.random for animation, shuffling and sampling.""",
    ),
    _note(
        "JS005",
        "MD5 or SHA-1 used as a hash",
        "JavaScript",
        """Both are broken for collision resistance, so neither proves that two
        inputs match or that content is unmodified. Both are also far too fast to
        stand between an attacker and a stolen password database.""",
        """Use crypto.createHash("sha256") for integrity. For passwords use a
        deliberately slow, salted algorithm — crypto.scrypt, or the argon2 or bcrypt
        packages — never a bare digest, however many times you repeat it.""",
    ),
    _note(
        "JS006",
        "TLS certificate verification disabled",
        "JavaScript",
        """rejectUnauthorized: false, or NODE_TLS_REJECT_UNAUTHORIZED=0, accepts any
        certificate, so an attacker on the network path can impersonate the server and
        read or alter everything sent to it — including the credentials you are
        sending to authenticate. Node prints a warning for this setting precisely
        because it disables the guarantee TLS exists to give.""",
        """Leave verification on. For an internal CA, pass it explicitly:
        new https.Agent({ ca: fs.readFileSync("ca.pem") }). For a self-signed
        certificate, add it to the trust store or pin it with the ca option. Never set
        NODE_TLS_REJECT_UNAUTHORIZED, which disables verification process-wide,
        including for calls you did not write.""",
    ),
    _note(
        "JV001",
        "Runtime.exec() with a concatenated command",
        "Java",
        """Runtime.exec with a single string splits on whitespace and, when invoked
        through sh -c, gives the shell everything you concatenated — so an argument
        containing ; or && runs another command. Quoting the value inside the string
        does not survive the shell.""",
        """Use ProcessBuilder with a list of arguments:
        new ProcessBuilder("git", "clone", url).start(). Each element is passed to the
        program as one argument regardless of its content. Do not invoke sh -c at all
        unless the whole command line is a constant.""",
    ),
    _note(
        "JV002",
        "Java deserialisation of data from outside the process",
        "Java",
        """ObjectInputStream.readObject reconstructs arbitrary object graphs and calls
        methods (readObject, readResolve, finalize) as it goes. With a common library
        on the classpath, a crafted byte stream chains those calls into command
        execution before your code ever sees the result — the classic gadget-chain
        attack. Checking the type after readObject returns is too late.""",
        """Do not deserialise untrusted Java objects. Use a data format with no
        behaviour — JSON via Jackson or Gson, bound to a specific class, with
        polymorphic type handling switched off. Where the stream cannot be replaced,
        install an ObjectInputFilter (Java 9+) that allows only an explicit list of
        classes, and authenticate the payload with an HMAC before reading it.""",
    ),
    _note(
        "JV003",
        "MD5 or SHA-1 used as a hash",
        "Java",
        """MessageDigest.getInstance("MD5") and "SHA-1" are collision-broken, so they
        cannot establish that a file or message is unaltered. They are also fast
        enough that an offline attacker tests billions of password guesses per second
        against their output.""",
        """Change the algorithm string to "SHA-256":
        MessageDigest.getInstance("SHA-256"). For passwords use a password hash
        instead — javax.crypto's PBKDF2WithHmacSHA256 with a high iteration count, or
        Argon2 or bcrypt from a maintained library, each with a per-password salt.""",
    ),
    _note(
        "SQL001",
        "SQL query built by concatenation",
        "SQL",
        """A value concatenated into SQL can close the string literal and continue the
        statement, which is how login checks are bypassed with ' OR '1'='1 and how
        data is extracted through UNION SELECT. Hand-written escaping breaks on
        multi-byte encodings, on numeric columns where no quotes are involved, and on
        anything nested.""",
        """Use bound parameters — placeholders in the SQL and values passed
        separately — so the database parses the statement before it ever sees the
        data. Every driver supports this. Stored procedures are only safe if they
        themselves use parameters rather than building dynamic SQL inside. Where an
        identifier must vary, validate it against a fixed list of permitted names.""",
    ),
    _note(
        "PH001",
        "PHP command execution function",
        "PHP",
        """system, exec, shell_exec, passthru and backticks all run their argument
        through the shell. Any request value that reaches one — $_GET, $_POST, a
        header, a filename — can add commands with ; or |, giving remote code
        execution as the web-server user. This is one of the most frequently
        exploited patterns in PHP applications.""",
        """Avoid shelling out. Where a PHP function exists for the job, use it. If an
        external program is genuinely required, escape every interpolated value with
        escapeshellarg() and the program name with escapeshellcmd(), or use
        proc_open with an argument array on PHP 7.4+. Never pass request data
        through unescaped.""",
    ),
    _note(
        "GO001",
        "exec.Command invoking a shell",
        "Go",
        """exec.Command("sh", "-c", cmd) hands the whole string to the shell, so any
        interpolated value is shell syntax. Go's own API makes the safe form just as
        convenient, so this pattern is usually a habit carried over from another
        language.""",
        """Call the program directly: exec.Command("git", "clone", url). Arguments
        are passed as a vector and never parsed by a shell. Use exec.CommandContext
        to bound how long it may run. Reserve sh -c for command lines that contain no
        variables at all.""",
    ),
    _note(
        "SEC001",
        "AWS access key id committed to the repository",
        "Secrets",
        """An access key pair is a long-lived credential for an AWS account. Keys
        scraped from public repositories are used within minutes, typically to launch
        compute for cryptomining and to enumerate whatever the key's policy allows.
        Deleting the line does not help: the key remains in git history and in every
        clone and fork already made.""",
        """Deactivate and delete the key in IAM first — treat it as compromised, not
        as possibly compromised — then check CloudTrail for use you did not make.
        Replace it with a credential that is not a secret in your code: an IAM role
        for anything running on AWS, or a short-lived token from your identity
        provider. If a static key is unavoidable, keep it in the environment or in
        AWS Secrets Manager. Finally, purge it from history with git filter-repo or
        the BFG, and rotate anything else that commit touched.""",
    ),
    _note(
        "SEC002",
        "Private key committed to the repository",
        "Secrets",
        """A private key is the thing that proves identity — for a TLS certificate, an
        SSH account, or a signing chain. Once it is in a repository it must be assumed
        to be in the hands of everyone who has ever cloned it, and it cannot be
        un-leaked. Anything it signs or decrypts is no longer trustworthy.""",
        """Revoke the certificate or remove the authorised key immediately, generate a
        new key pair, and reissue. Store the new private key outside the repository —
        in the environment, a secrets manager, or a file deployed by configuration
        management with restrictive permissions — and add its path to .gitignore.
        Purge the old key from git history, and remember that any signature or
        session it protected before revocation should be treated as suspect.""",
    ),
    _note(
        "SEC003",
        "Provider API token in source",
        "Secrets",
        """Tokens for GitHub, Slack, Stripe, cloud providers and similar services
        usually carry broad permissions on the account that issued them: reading
        private repositories, posting as a user, moving money. Public repositories are
        scanned continuously for these patterns, so exposure is measured in minutes,
        not months.""",
        """Revoke the token in the provider's console before anything else, then issue
        a replacement with the narrowest scope that works and, where the provider
        supports it, an expiry. Read it from the environment at runtime. Check the
        provider's audit log for use during the exposure window, and purge the value
        from git history.""",
    ),
    _note(
        "SEC004",
        "Database URL containing a password",
        "Secrets",
        """A connection string with credentials in it is a complete database login,
        and it tends to spread further than other secrets: into logs, error pages,
        screenshots and issue reports, because the URL is treated as configuration
        rather than as a password.""",
        """Keep the URL in an environment variable and out of the repository; commit a
        .env.example with the password removed instead. Rotate the exposed password on
        the database itself. Check that the URL is not being logged — log the host and
        database name, never the whole string. Where the platform supports it, prefer
        an authentication method with no password at all, such as IAM database
        authentication or a client certificate.""",
    ),
    _note(
        "SEC005",
        "Credential assigned in source code",
        "Secrets",
        """Any password, key or token written into source is readable by everyone with
        access to the repository, survives in git history after deletion, and is
        copied into every clone, fork, CI cache and backup. It also cannot be changed
        per environment, so the same value ends up in development and production.""",
        """Move it into the environment and load it at startup, failing loudly if it
        is missing — a configuration error at boot is far better than a default
        credential in production. Keep local values in a .gitignore'd .env file, and
        commit a .env.example listing the names with the values blank. Then rotate the
        exposed credential and purge it from git history.""",
    ),
)

NOTES_BY_RULE: dict[str, RuleNote] = {note.rule_id: note for note in RULE_NOTES}


__all__ = ["NOTES_BY_RULE", "RULE_NOTES", "RuleNote"]
