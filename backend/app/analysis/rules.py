"""The rule catalogue: one place where every rule's identity lives.

Each rule carries its own severity, confidence, CWE and OWASP category, so the
analysers below only decide *whether* a rule matched — never how bad it is.
That separation is what makes the catalogue reviewable: you can read this file
alone and argue with the severities without reading a single AST visitor.

Confidence is set per rule and reflects how much the pattern can lie:

* HIGH   — the code is definitionally the problem (`os.system`, `shell=True`).
* MEDIUM — the shape is right but intent is inferred (a concatenated string
  that looks like SQL; MD5 that might be hashing a cache key, not a password).
* LOW    — worth a human look, nothing more.

Every rule in here has two tests: one file that must trigger it, and one that
must **not**. A rule with no counterexample test is a rule nobody has checked.
"""

from dataclasses import dataclass

from app.analysis.findings import Confidence, Severity


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    message: str
    severity: Severity
    confidence: Confidence
    cwe_id: str | None = None
    owasp_category: str | None = None


def _rule(
    identifier: str,
    title: str,
    message: str,
    severity: Severity,
    confidence: Confidence,
    cwe_id: str | None = None,
    owasp: str | None = None,
) -> Rule:
    return Rule(identifier, title, message, severity, confidence, cwe_id, owasp)


# --- Python (AST) ---------------------------------------------------------

PY_EVAL_EXEC = _rule(
    "PY001",
    "eval() or exec() on a non-literal value",
    "Executing a value that is built at runtime lets anything that reaches it "
    "run arbitrary Python. Parse the data instead (ast.literal_eval, json.loads), "
    "or dispatch through an explicit mapping.",
    Severity.CRITICAL,
    Confidence.HIGH,
    "CWE-95",
    "A03:2021 Injection",
)
PY_SHELL_TRUE = _rule(
    "PY002",
    "subprocess called with shell=True",
    "With shell=True the command string is handed to a shell, so a value like "
    "'; rm -rf /' inside it is executed. Pass the command as a list of arguments "
    "and leave shell off.",
    Severity.HIGH,
    Confidence.HIGH,
    "CWE-78",
    "A03:2021 Injection",
)
PY_OS_SYSTEM = _rule(
    "PY003",
    "os.system() or os.popen()",
    "Both run their argument through a shell. Use subprocess.run() with a list "
    "of arguments, which never involves a shell.",
    Severity.HIGH,
    Confidence.HIGH,
    "CWE-78",
    "A03:2021 Injection",
)
PY_YAML_LOAD = _rule(
    "PY004",
    "yaml.load() without a safe loader",
    "The default loader constructs arbitrary Python objects, so a crafted YAML "
    "file can execute code. Use yaml.safe_load().",
    Severity.HIGH,
    Confidence.HIGH,
    "CWE-502",
    "A08:2021 Software and Data Integrity Failures",
)
PY_PICKLE = _rule(
    "PY005",
    "pickle used on external data",
    "Unpickling runs code by design. For anything that crosses a trust boundary "
    "use JSON, or sign the payload and verify it before unpickling.",
    Severity.HIGH,
    Confidence.MEDIUM,
    "CWE-502",
    "A08:2021 Software and Data Integrity Failures",
)
PY_HARDCODED_SECRET = _rule(
    "PY006",
    "Credential assigned in source code",
    "A secret in source is a secret in every clone, branch and backup of the "
    "repository. Read it from the environment and rotate this one.",
    Severity.HIGH,
    Confidence.MEDIUM,
    "CWE-798",
    "A07:2021 Identification and Authentication Failures",
)
PY_WEAK_HASH = _rule(
    "PY007",
    "Weak hash algorithm (MD5 or SHA-1)",
    "Both are broken for anything security-related. Use SHA-256 for integrity, "
    "and a password hash (scrypt, bcrypt, argon2) for passwords.",
    Severity.MEDIUM,
    Confidence.MEDIUM,
    "CWE-327",
    "A02:2021 Cryptographic Failures",
)
PY_TLS_VERIFY_OFF = _rule(
    "PY008",
    "TLS certificate verification disabled",
    "verify=False accepts any certificate, so anyone on the path can read and "
    "change the traffic. If it is a private CA, point verify= at its bundle.",
    Severity.HIGH,
    Confidence.HIGH,
    "CWE-295",
    "A02:2021 Cryptographic Failures",
)
PY_FLASK_DEBUG = _rule(
    "PY009",
    "Flask started with debug=True",
    "The debugger exposes an interactive console on error pages — remote code "
    "execution if it reaches production. Drive it from configuration instead.",
    Severity.MEDIUM,
    Confidence.HIGH,
    "CWE-489",
    "A05:2021 Security Misconfiguration",
)
PY_SQL_BUILT = _rule(
    "PY010",
    "SQL query built by string formatting",
    "Values concatenated or interpolated into SQL are parsed as SQL. Pass them "
    "as parameters (execute(query, params)) and let the driver escape them.",
    Severity.CRITICAL,
    Confidence.MEDIUM,
    "CWE-89",
    "A03:2021 Injection",
)
PY_WEAK_RANDOM = _rule(
    "PY011",
    "random module used for a security value",
    "random is a predictable PRNG: given a few outputs the rest can be derived. "
    "Use secrets.token_urlsafe() for tokens and passwords.",
    Severity.MEDIUM,
    Confidence.MEDIUM,
    "CWE-338",
    "A02:2021 Cryptographic Failures",
)
PY_MKTEMP = _rule(
    "PY012",
    "tempfile.mktemp() is unsafe",
    "It returns a name, not a file, so another process can create that path "
    "first. Use tempfile.mkstemp() or NamedTemporaryFile().",
    Severity.MEDIUM,
    Confidence.HIGH,
    "CWE-377",
    "A01:2021 Broken Access Control",
)
PY_JWT_UNVERIFIED = _rule(
    "PY013",
    "JWT decoded without verifying the signature",
    "An unverified token is just a string the client wrote. Verify the "
    "signature and pin the algorithm.",
    Severity.CRITICAL,
    Confidence.HIGH,
    "CWE-347",
    "A02:2021 Cryptographic Failures",
)
PY_UNVERIFIED_SSL_CONTEXT = _rule(
    "PY014",
    "Unverified SSL context created",
    "ssl._create_unverified_context() disables certificate checking for every "
    "connection that uses it.",
    Severity.HIGH,
    Confidence.HIGH,
    "CWE-295",
    "A02:2021 Cryptographic Failures",
)
PY_XML_PARSE = _rule(
    "PY015",
    "XML parsed with a parser that resolves entities",
    "Standard library XML parsers can be made to read local files or hang on a "
    "billion-laughs payload. Use defusedxml for untrusted XML.",
    Severity.MEDIUM,
    Confidence.MEDIUM,
    "CWE-611",
    "A05:2021 Security Misconfiguration",
)

# --- Patterns (JavaScript/TypeScript, Java, PHP, Go, and anything textual) --

JS_EVAL = _rule(
    "JS001",
    "eval() on a non-literal value",
    "Anything that reaches this string runs as JavaScript. Use JSON.parse() for "
    "data and a lookup table for dispatch.",
    Severity.CRITICAL,
    Confidence.HIGH,
    "CWE-95",
    "A03:2021 Injection",
)
JS_CHILD_PROCESS = _rule(
    "JS002",
    "child_process.exec() with an interpolated command",
    "exec() runs the string in a shell. Use execFile() or spawn() with an argument array.",
    Severity.HIGH,
    Confidence.HIGH,
    "CWE-78",
    "A03:2021 Injection",
)
JS_INNER_HTML = _rule(
    "JS003",
    "HTML assigned from a variable",
    "innerHTML and dangerouslySetInnerHTML parse their input as HTML, so a "
    "value containing a script tag or an onerror attribute executes. Set "
    "textContent, or sanitise with DOMPurify first.",
    Severity.MEDIUM,
    Confidence.MEDIUM,
    "CWE-79",
    "A03:2021 Injection",
)
JS_MATH_RANDOM = _rule(
    "JS004",
    "Math.random() used for a security value",
    "Math.random() is predictable. Use crypto.randomUUID() or crypto.getRandomValues().",
    Severity.MEDIUM,
    Confidence.MEDIUM,
    "CWE-338",
    "A02:2021 Cryptographic Failures",
)
JS_WEAK_HASH = _rule(
    "JS005",
    "Weak hash algorithm (MD5 or SHA-1)",
    "Use SHA-256, or a password hash such as bcrypt or argon2 for passwords.",
    Severity.MEDIUM,
    Confidence.MEDIUM,
    "CWE-327",
    "A02:2021 Cryptographic Failures",
)
JS_TLS_OFF = _rule(
    "JS006",
    "TLS certificate verification disabled",
    "rejectUnauthorized: false (or NODE_TLS_REJECT_UNAUTHORIZED=0) accepts any "
    "certificate, which removes the point of TLS.",
    Severity.HIGH,
    Confidence.HIGH,
    "CWE-295",
    "A02:2021 Cryptographic Failures",
)
JAVA_RUNTIME_EXEC = _rule(
    "JV001",
    "Runtime.exec() with a concatenated command",
    "Build the command as a String[] so no shell parsing happens, or avoid shelling out entirely.",
    Severity.HIGH,
    Confidence.MEDIUM,
    "CWE-78",
    "A03:2021 Injection",
)
JAVA_DESERIALIZE = _rule(
    "JV002",
    "Java deserialisation of external data",
    "ObjectInputStream.readObject() instantiates whatever the stream names, "
    "which is remote code execution with the right classpath. Use a data format.",
    Severity.HIGH,
    Confidence.MEDIUM,
    "CWE-502",
    "A08:2021 Software and Data Integrity Failures",
)
JAVA_WEAK_HASH = _rule(
    "JV003",
    "Weak hash algorithm (MD5 or SHA-1)",
    'MessageDigest.getInstance("SHA-256"), or a password hash for passwords.',
    Severity.MEDIUM,
    Confidence.MEDIUM,
    "CWE-327",
    "A02:2021 Cryptographic Failures",
)
SQL_CONCATENATION = _rule(
    "SQL001",
    "SQL query built by concatenation",
    "A value joined into a query string is parsed as SQL. Use a prepared "
    "statement with bound parameters.",
    Severity.CRITICAL,
    Confidence.MEDIUM,
    "CWE-89",
    "A03:2021 Injection",
)
PHP_COMMAND = _rule(
    "PH001",
    "PHP command execution function",
    "system(), shell_exec(), passthru() and eval() run their argument. Avoid "
    "them, or use escapeshellarg() on every value.",
    Severity.CRITICAL,
    Confidence.MEDIUM,
    "CWE-78",
    "A03:2021 Injection",
)
GO_SHELL = _rule(
    "GO001",
    "exec.Command invoking a shell",
    "Running sh -c re-introduces shell parsing. Call the program directly with its arguments.",
    Severity.HIGH,
    Confidence.MEDIUM,
    "CWE-78",
    "A03:2021 Injection",
)

# --- Secrets (every text file) --------------------------------------------

SECRET_AWS_KEY = _rule(
    "SEC001",
    "AWS access key id in source",
    "Rotate this key now: it is in every clone and every backup of this "
    "repository. Load credentials from the environment or an instance role.",
    Severity.CRITICAL,
    Confidence.HIGH,
    "CWE-798",
    "A07:2021 Identification and Authentication Failures",
)
SECRET_PRIVATE_KEY = _rule(
    "SEC002",
    "Private key committed to the repository",
    "Revoke and reissue this key. Private keys belong in a secret store, never in version control.",
    Severity.CRITICAL,
    Confidence.HIGH,
    "CWE-798",
    "A02:2021 Cryptographic Failures",
)
SECRET_PROVIDER_TOKEN = _rule(
    "SEC003",
    "Provider API token in source",
    "This looks like a live token for a third-party service. Revoke it and read "
    "it from configuration.",
    Severity.CRITICAL,
    Confidence.HIGH,
    "CWE-798",
    "A07:2021 Identification and Authentication Failures",
)
SECRET_CONNECTION_STRING = _rule(
    "SEC004",
    "Database URL containing a password",
    "The credential travels with the code. Build the URL from environment variables at runtime.",
    Severity.HIGH,
    Confidence.MEDIUM,
    "CWE-798",
    "A05:2021 Security Misconfiguration",
)
SECRET_GENERIC = _rule(
    "SEC005",
    "Credential assigned in source code",
    "Move it to configuration and rotate the value.",
    Severity.HIGH,
    Confidence.LOW,
    "CWE-798",
    "A07:2021 Identification and Authentication Failures",
)

ALL_RULES: tuple[Rule, ...] = (
    PY_EVAL_EXEC,
    PY_SHELL_TRUE,
    PY_OS_SYSTEM,
    PY_YAML_LOAD,
    PY_PICKLE,
    PY_HARDCODED_SECRET,
    PY_WEAK_HASH,
    PY_TLS_VERIFY_OFF,
    PY_FLASK_DEBUG,
    PY_SQL_BUILT,
    PY_WEAK_RANDOM,
    PY_MKTEMP,
    PY_JWT_UNVERIFIED,
    PY_UNVERIFIED_SSL_CONTEXT,
    PY_XML_PARSE,
    JS_EVAL,
    JS_CHILD_PROCESS,
    JS_INNER_HTML,
    JS_MATH_RANDOM,
    JS_WEAK_HASH,
    JS_TLS_OFF,
    JAVA_RUNTIME_EXEC,
    JAVA_DESERIALIZE,
    JAVA_WEAK_HASH,
    SQL_CONCATENATION,
    PHP_COMMAND,
    GO_SHELL,
    SECRET_AWS_KEY,
    SECRET_PRIVATE_KEY,
    SECRET_PROVIDER_TOKEN,
    SECRET_CONNECTION_STRING,
    SECRET_GENERIC,
)

RULES_BY_ID: dict[str, Rule] = {rule.id: rule for rule in ALL_RULES}
