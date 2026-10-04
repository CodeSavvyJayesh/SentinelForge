"""The names the flow walk has to know: where input comes from, what makes it
safe, and which calls fetch or run something.

Every entry is a claim about a library, so every entry is here in one file
where it can be disputed, rather than spread through the code that uses it.
Nothing in this file is derived from a benchmark's test cases: a name is here
because of what the function does.
"""

from collections.abc import Callable

from app.analysis.python_values import COMMAND, HTML, LDAP, PATH, XPATH

# --- names the walk has to know about ------------------------------------------

# The object a framework hands out for "the request being answered".
REQUEST_OBJECTS = ("flask.request", "quart.request", "bottle.request")
REQUEST_PATHS = frozenset(f"{name}.path" for name in REQUEST_OBJECTS)
# Parts of a request the caller does not write: who they are, how they
# connected, what the framework worked out. Reading one gives nothing to inject.
REQUEST_NOT_INPUT = frozenset(
    {
        "method", "endpoint", "blueprint", "blueprints", "url_rule", "remote_addr", "scheme",
        "is_secure", "is_json", "is_ajax", "accepts", "content_length", "max_content_length",
        "user", "auth", "session", "site", "resolver_match", "urlconf", "app", "state",
        "current_app", "csrf_processing_done", "get_port",
    }
)  # fmt: skip
# Parts that are the caller's but can only name a place on this site.
REQUEST_SAME_SITE = frozenset(
    {
        "path", "path_info", "full_path", "script_root", "root_path", "get_full_path",
        "get_full_path_info", "build_absolute_uri", "get_host", "host", "host_url", "url_root",
        "base_url", "url",
    }
)  # fmt: skip
# Route converters and annotations that make a parameter something other than text.
NOT_TEXT = frozenset({"int", "float", "bool", "uuid", "UUID", "Decimal", "date", "datetime"})
# Frameworks in which a string returned from a route is sent as an HTML page.
HTML_BY_DEFAULT = frozenset({"flask", "quart", "bottle"})
# Calls of a web framework whose result is not markup written by this code: a
# rendered template is escaped by the template engine, JSON is not a page.
HTML_SAFE_CALLS = frozenset(
    {
        "render_template", "render", "render_to_string", "render_to_response", "jsonify",
        "JsonResponse", "redirect", "url_for", "reverse", "send_file", "send_from_directory",
        "abort", "stream_template",
    }
)  # fmt: skip
# Calls of a web framework that build an address of this site from a route name.
SITE_ADDRESS_CALLS = frozenset({"url_for", "reverse", "reverse_lazy", "resolve_url"})
# Functions that answer "is this address on a host we allow?".
REDIRECT_VALIDATORS = frozenset({"url_has_allowed_host_and_scheme", "is_safe_url"})
ROUTE_DECORATORS = frozenset({"route", "get", "post", "put", "delete", "patch"})

RANDOM_FUNCTIONS = frozenset(
    {
        "random", "randint", "randrange", "choice", "choices", "sample", "getrandbits",
        "randbytes", "uniform", "normalvariate", "gauss", "triangular", "shuffle",
    }
)  # fmt: skip

# Results that are numbers or booleans cannot carry an injection.
NUMERIC_FUNCTIONS = frozenset({"int", "float", "bool", "len", "ord", "abs", "round", "hash", "id"})

# Function -> the kinds of use its result is safe for. Matched on the name
# after imports are resolved.
SANITISERS: dict[str, frozenset[str]] = {
    "html.escape": frozenset({HTML}),
    "markupsafe.escape": frozenset({HTML}),
    "flask.escape": frozenset({HTML}),
    "cgi.escape": frozenset({HTML}),
    "bleach.clean": frozenset({HTML}),
    "django.utils.html.escape": frozenset({HTML}),
    "xml.sax.saxutils.escape": frozenset({HTML}),
    "xml.sax.saxutils.quoteattr": frozenset({HTML}),
    # A response that is not HTML written by this code.
    "json.dumps": frozenset({HTML}),
    "flask.json.dumps": frozenset({HTML}),
    "flask.jsonify": frozenset({HTML}),
    "flask.redirect": frozenset({HTML}),
    "flask.render_template": frozenset({HTML}),
    "flask.url_for": frozenset({HTML}),
    "shlex.quote": frozenset({COMMAND}),
    "pipes.quote": frozenset({COMMAND}),
    "os.path.basename": frozenset({PATH}),
    "werkzeug.utils.secure_filename": frozenset({PATH}),
    "ldap3.utils.conv.escape_filter_chars": frozenset({LDAP}),
    "ldap.filter.escape_filter_chars": frozenset({LDAP}),
}
# A project's own escaping helper, recognised by what it is called.
HTML_ESCAPE_NAMES = frozenset(
    {"escape_for_html", "escape_html", "html_escape", "htmlescape", "escapehtml"}
)

# A response object stands for its body: (body, status, headers) -> body.
RESPONSE_FUNCTIONS = frozenset({"flask.make_response", "flask.Response", "make_response"})

PATH_CONSTRUCTORS = frozenset(
    {"pathlib.Path", "pathlib.PurePath", "pathlib.PosixPath", "pathlib.WindowsPath"}
)

# Calls that fetch or run something. What they are given matters to the rules;
# what they give back is what was stored or printed, not the value passed in —
# a file's contents are not the file name. So their result is "not known",
# never "request data".
FILE_CALLS = frozenset(
    {
        "open", "io.open", "codecs.open", "os.open", "os.remove", "os.unlink", "os.rmdir",
        "os.mkdir", "os.makedirs", "os.listdir", "os.scandir", "os.stat", "os.chmod",
        "os.rename", "os.replace", "os.path.exists", "os.path.isfile", "os.path.isdir",
        "os.path.getsize", "shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.move",
        "shutil.rmtree", "flask.send_file",
    }
)  # fmt: skip
SUBPROCESS_CALLS = frozenset(
    {
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
    }
)
# Function -> the position of the query among its arguments.
XPATH_CALLS = {"elementpath.select": 1, "lxml.etree.XPath": 0, "lxml.etree.ETXPath": 0}
FETCH_CALLS = frozenset(
    {
        "urllib.request.urlopen", "requests.get", "requests.post", "requests.put",
        "requests.delete", "requests.patch", "requests.head", "requests.request",
        "httpx.get", "httpx.post", "httpx.put", "httpx.delete", "httpx.patch", "httpx.request",
    }
)  # fmt: skip
LOOKUP_CALLS = (
    FILE_CALLS | SUBPROCESS_CALLS | FETCH_CALLS | XPATH_CALLS.keys() | {"os.system", "os.popen"}
)
LOOKUP_METHODS = frozenset({"xpath", "execute", "executemany", "executescript"})

# Methods that change the list, set or dict they are called on.
MUTATING_METHODS = frozenset(
    {
        "append", "appendleft", "extend", "extendleft", "insert", "remove", "pop", "popitem",
        "clear", "sort", "reverse", "add", "discard", "update", "setdefault",
    }
)  # fmt: skip
URL_PARSERS = frozenset({"urllib.parse.urlparse", "urllib.parse.urlsplit"})

# Methods that put their argument into the object they are called on.
ABSORBING_METHODS = frozenset(
    {
        "write", "writelines", "append", "appendleft", "extend", "add", "update", "insert",
        "put", "push", "feed", "setdefault", "set",
    }
)  # fmt: skip

# str and bytes methods with no side effects, safe to apply to two literals.
PURE_METHODS = frozenset(
    {
        "lower", "upper", "strip", "lstrip", "rstrip", "split", "rsplit", "replace", "find",
        "rfind", "startswith", "endswith", "encode", "decode", "join", "zfill", "title",
        "capitalize", "isdigit", "isalpha", "isalnum", "count", "format", "removeprefix",
        "removesuffix", "casefold", "swapcase", "partition", "rpartition",
    }
)  # fmt: skip
PURE_FUNCTIONS: dict[str, Callable[..., object]] = {
    "len": len,
    "str": str,
    "int": int,
    "bool": bool,
    "repr": repr,
    "abs": abs,
    "min": min,
    "max": max,
}

# Library functions whose result is made of their arguments and nothing else.
# Calling one on a literal gives something as trustworthy as the literal;
# calling an unknown function does not, because it may read a socket.
PURE_CALLS = frozenset(
    {
        "str", "bytes", "repr", "format", "ascii", "tuple", "list", "sorted", "reversed",
        "base64.b64encode", "base64.b64decode", "base64.urlsafe_b64encode",
        "base64.urlsafe_b64decode", "base64.standard_b64encode", "base64.standard_b64decode",
        "base64.b32encode", "base64.b32decode", "base64.b16encode", "base64.b16decode",
        "binascii.hexlify", "binascii.unhexlify", "codecs.encode", "codecs.decode",
        "urllib.parse.quote", "urllib.parse.quote_plus", "urllib.parse.unquote",
        "urllib.parse.unquote_plus", "urllib.parse.urlparse", "urllib.parse.urlsplit",
        "urllib.parse.urljoin", "urllib.parse.urlencode", "html.unescape",
        "os.path.join", "os.path.normpath", "os.path.abspath", "os.path.realpath",
        "os.path.dirname", "os.path.splitext", "os.path.expanduser",
    }
)  # fmt: skip

QUOTES = frozenset({"'", '"'})
# Rejecting or replacing quotes stops a value breaking out of a quoted literal
# in an XPath expression. It is deliberately not treated as making SQL safe:
# the fix for SQL is a bound parameter, and a quote check is not one.
QUOTE_KINDS = frozenset({XPATH})
HOST_ATTRIBUTES = frozenset({"netloc", "hostname", "host", "domain"})
WHOLE_VALUE_CHECKS = frozenset(
    {"isdigit", "isalnum", "isalpha", "isnumeric", "isdecimal", "isidentifier"}
)


WEB_FRAMEWORKS = frozenset(
    {
        "flask", "quart", "bottle", "django", "rest_framework", "fastapi", "starlette",
        "aiohttp", "sanic", "tornado", "pyramid", "falcon", "werkzeug",
    }
)  # fmt: skip
