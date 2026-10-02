"""Building the diff, and refusing the proposals that should not be shown.

The diff itself needs little testing — it is ``difflib`` — so what is tested is
the part that carries judgement: which model outputs are thrown away. Each of
the refusals below corresponds to something a small model actually does when
asked to fix a vulnerability.
"""

import pytest

from app.patching import diffing

BEFORE = [
    "def digest(value):\n",
    "    return hashlib.md5(value).hexdigest()\n",
]


def test_the_diff_is_a_real_unified_diff(tmp_path=None) -> None:  # noqa: ANN001
    after = ["def digest(value):\n", "    return hashlib.sha256(value).hexdigest()\n"]

    diff = diffing.build("app/hash.py", BEFORE, after)

    assert diff.text.startswith("--- a/app/hash.py\n+++ b/app/hash.py\n@@")
    assert "-    return hashlib.md5(value).hexdigest()" in diff.text
    assert "+    return hashlib.sha256(value).hexdigest()" in diff.text
    assert diff.added == 1
    assert diff.removed == 1


def test_the_file_markers_are_not_counted_as_changed_lines(tmp_path=None) -> None:  # noqa: ANN001
    """``---`` and ``+++`` start with the same characters as changed lines.

    Counting them would report every one-line fix as two added and two removed,
    which is the number shown in the UI and recorded for the evaluation.
    """
    diff = diffing.build("a.py", BEFORE, [*BEFORE, "print(1)\n"])

    assert diff.added == 1
    assert diff.removed == 0


def test_a_diff_of_a_line_without_a_trailing_newline_still_ends_in_one(
    tmp_path=None,  # noqa: ANN001
) -> None:
    """difflib emits a bare "\\ No newline at end of file" marker line.

    Left unterminated, the stored diff has a line running into the next and no
    tool can read it.
    """
    diff = diffing.build("a.py", ["x = 1"], ["x = 2"])

    assert diff.text.endswith("\n")
    assert all(line for line in diff.text.split("\n")[:-1])


# --- refusals -------------------------------------------------------------


def test_an_unchanged_region_is_refused() -> None:
    """The most common bad answer: the code back verbatim, plus "fixed it".

    Storing this means showing somebody a fix that fixes nothing, which is
    worse than showing them a failure.
    """
    diff = diffing.build("a.py", BEFORE, list(BEFORE))

    with pytest.raises(diffing.PatchRejected, match="same code"):
        diffing.check(diff, replaced_lines=len(BEFORE))


def test_a_rewrite_is_refused() -> None:
    after = [*BEFORE[:1], *[f"    step_{n}()\n" for n in range(60)]]
    diff = diffing.build("a.py", BEFORE, after)

    with pytest.raises(diffing.PatchRejected, match="rewrite rather than a fix"):
        diffing.check(diff, replaced_lines=len(BEFORE))


def test_a_reasonable_expansion_is_allowed() -> None:
    """A parameterised query is legitimately more lines than a string concat."""
    after = [
        "def digest(value):\n",
        "    if value is None:\n",
        "        raise ValueError('value is required')\n",
        "    return hashlib.sha256(value).hexdigest()\n",
    ]
    diff = diffing.build("a.py", BEFORE, after)

    diffing.check(diff, replaced_lines=len(BEFORE))  # does not raise


def test_deleting_the_vulnerable_code_is_refused() -> None:
    """The failure mode this whole phase is arranged against.

    Removing the offending lines makes the finding disappear on the next scan.
    Phase 11 would then certify it as a successful fix, because from the
    scanner's point of view it is indistinguishable from one.
    """
    before = [f"line_{n}()\n" for n in range(20)]
    after = before[:2]
    diff = diffing.build("a.py", before, after)

    with pytest.raises(diffing.PatchRejected, match="mostly deletes code"):
        diffing.check(diff, replaced_lines=len(before))


def test_a_small_net_removal_is_allowed() -> None:
    """Some correct fixes are net deletions, and must not be refused.

    Removing a hardcoded-credential block is smaller than what it replaces. The
    numbers matter: this removes four lines and adds one, so it only passes
    while the allowance is above three — a test that removed one and added one
    would pass even with the allowance set to zero, and would prove nothing.
    """
    before = [
        "USER = 'admin'\n",
        "PASSWORD = 'hunter2'\n",
        "TOKEN = 'abc123'\n",
        "connect(USER, PASSWORD, TOKEN)\n",
    ]
    after = ["connect(*credentials_from_environment())\n"]
    diff = diffing.build("a.py", before, after)

    assert diff.removed - diff.added == 3
    diffing.check(diff, replaced_lines=len(before))  # does not raise


# --- syntax ---------------------------------------------------------------


def test_python_that_does_not_parse_is_refused() -> None:
    with pytest.raises(diffing.PatchRejected, match="does not parse as Python"):
        diffing.check_syntax("app/x.py", ["def broken(:\n", "    pass\n"])


def test_valid_python_passes() -> None:
    diffing.check_syntax("app/x.py", ["def fine():\n", "    return 1\n"])


def test_other_languages_are_not_checked() -> None:
    """Stated, not hidden: there is no Java parser here, and pulling one in to
    check a patch would be a larger undertaking than the patching. Phase 11's
    re-scan is what catches a broken file in those languages."""
    diffing.check_syntax("Report.java", ["this is not java at all {{{\n"])


def test_the_syntax_check_does_not_execute_the_code(tmp_path) -> None:  # noqa: ANN001
    """``ast.parse`` builds a tree and evaluates nothing.

    The code being parsed came out of somebody else's repository, so this is
    the same property Phase 5 relies on — asserted rather than assumed.
    """
    marker = tmp_path / "executed.txt"
    source = [
        "import pathlib\n",
        f"pathlib.Path({str(marker)!r}).write_text('executed')\n",
    ]

    diffing.check_syntax("x.py", source)

    assert not marker.exists()


# --- substance --------------------------------------------------------------


@pytest.mark.parametrize(
    ("line", "path"),
    [
        ("", "a.py"),
        ("    pass", "a.py"),
        ("    # removed for security", "a.py"),
        ("    ...", "a.py"),
        ("        // removed", "Report.java"),
        ("        /* removed */", "Report.java"),
        ("         * still inside the comment", "Report.java"),
        ("        ;", "Report.java"),
        ("-- removed", "q.sql"),
    ],
)
def test_lines_that_do_nothing_are_recognised(line: str, path: str) -> None:
    assert diffing.is_inert(line, path)


@pytest.mark.parametrize(
    ("line", "path"),
    [
        ("    return hashlib.sha256(value).hexdigest()", "a.py"),
        # `#` is a comment in Python and a directive in C.
        ("#include <openssl/sha.h>", "a.c"),
        # A dereference, not the middle of a block comment.
        ("*p = 0;", "a.c"),
        # `//` and `*` open nothing in Python. On a continuation line they are
        # floor division and multiplication — code, at the start of a line.
        ("         // divisor)", "a.py"),
        ("         * rate)", "a.py"),
        ("    return null;", "Report.java"),
    ],
)
def test_lines_that_do_something_are_not_mistaken_for_comments(line: str, path: str) -> None:
    assert not diffing.is_inert(line, path)


def test_replacing_code_with_a_no_op_is_refused() -> None:
    """One line out, one line in — the size check sees a net change of zero.

    This is the tidy version of deleting the vulnerable code, and it would
    otherwise reach a reviewer as a one-line "fix".
    """
    with pytest.raises(diffing.PatchRejected, match="nothing that runs"):
        diffing.check_substance("a.py", ("    pass",))

    with pytest.raises(diffing.PatchRejected, match="nothing that runs"):
        diffing.check_substance("a.py", ("    # removed: insecure", ""))


def test_a_change_with_any_real_code_in_it_is_not_refused() -> None:
    diffing.check_substance("a.py", ("    # use a strong hash", "    return sha256(v)"))


def test_the_diff_carries_its_added_lines() -> None:
    after = ["def digest(value):\n", "    return hashlib.sha256(value).hexdigest()\n"]

    diff = diffing.build("a.py", BEFORE, after)

    assert diff.added_lines == ("    return hashlib.sha256(value).hexdigest()",)


def test_lines_that_look_like_file_markers_are_still_counted() -> None:
    """An added ``++i;`` is the diff line ``+++i;``, and a removed SQL comment
    ``-- x`` is ``--- x``. Recognising headers by prefix drops both from the
    count; the headers are the first two lines and are skipped by position."""
    diff = diffing.build("a.c", ["int i = 0;\n", "-- x\n"], ["int i = 0;\n", "++i;\n"])

    assert diff.added == 1
    assert diff.removed == 1
    assert diff.added_lines == ("++i;",)
