"""Applying a stored diff, with no fuzz and no offset.

`git apply` and `patch` are helpful: they will slide a hunk a few lines to find
somewhere it fits. A hunk that has been slid is a patch applied to code nobody
reviewed, so this applier refuses instead. Most of the tests below are about a
refusal.
"""

import pytest

from app.patching import apply as patch_apply
from app.patching import diffing
from app.patching.apply import PatchDoesNotApply

BEFORE = [
    "import hashlib\n",
    "\n",
    "\n",
    "def digest(value):\n",
    "    return hashlib.md5(value).hexdigest()\n",
    "\n",
    "\n",
    "def other():\n",
    "    return 1\n",
]
AFTER = [line.replace("md5", "sha256") for line in BEFORE]


def diff_of(before: list[str], after: list[str], path: str = "app.py") -> str:
    return diffing.build(path, before, after).text


def roundtrip(before: list[str], after: list[str]) -> list[str]:
    return patch_apply.apply(before, patch_apply.parse(diff_of(before, after)))


# --- applying -------------------------------------------------------------


def test_a_one_line_change_applies() -> None:
    assert roundtrip(BEFORE, AFTER) == AFTER


@pytest.mark.parametrize(
    ("before", "after"),
    [
        # an insertion
        (BEFORE, [*BEFORE[:4], "    value = bytes(value)\n", *BEFORE[4:]]),
        # a removal
        (BEFORE, [*BEFORE[:7], *BEFORE[8:]]),
        # two hunks, far enough apart to be separate
        (
            [f"line_{n} = {n}\n" for n in range(40)],
            [
                "line_0 = 0\n",
                "first = True\n",
                *[f"line_{n} = {n}\n" for n in range(2, 38)],
                "second = True\n",
                "line_39 = 39\n",
            ],
        ),
        # appended at the very end
        (BEFORE, [*BEFORE, "\n", "print(other())\n"]),
        # prepended at the very start
        (BEFORE, ["# header\n", *BEFORE]),
        # a file that is one line, replaced whole
        (["x = 1\n"], ["x = 2\n"]),
    ],
)
def test_what_difflib_writes_this_can_apply(before: list[str], after: list[str]) -> None:
    """The property the whole phase rests on: every diff Phase 10 can produce,
    Phase 11 can apply, and the result is exactly the file Phase 10 meant."""
    assert roundtrip(before, after) == after


def test_a_crlf_file_keeps_its_line_endings() -> None:
    before = [line.replace("\n", "\r\n") for line in BEFORE]
    after = [line.replace("\n", "\r\n") for line in AFTER]

    patched = roundtrip(before, after)

    assert patched == after
    assert all(line.endswith("\r\n") for line in patched)


def test_a_diff_stored_with_unix_endings_still_applies_to_a_crlf_file() -> None:
    """The diff travels through a database and a JSON API. The file's endings
    are the file's, whatever happened to the diff on the way."""
    crlf = [line.replace("\n", "\r\n") for line in BEFORE]
    stored_with_lf = diff_of(BEFORE, AFTER)

    patched = patch_apply.apply(crlf, patch_apply.parse(stored_with_lf))

    assert patched == [line.replace("\n", "\r\n") for line in AFTER]


def test_a_file_without_a_final_newline_does_not_gain_one() -> None:
    before = ["a = 1\n", "b = md5()"]
    after = ["a = 1\n", "b = sha256()"]

    assert roundtrip(before, after) == after


def test_a_removed_sql_comment_is_not_mistaken_for_a_file_header() -> None:
    """Removing the line ``-- drop it`` appears in a diff as ``--- drop it``.

    Anything that recognises file headers by how a line starts reads that as a
    second file. Hunks are read by the counts in their header instead.
    """
    before = ["SELECT 1;\n", "-- drop it\n", "SELECT 2;\n"]
    after = ["SELECT 1;\n", "SELECT 2;\n"]

    parsed = patch_apply.parse(diff_of(before, after, "q.sql"))

    assert parsed.removed == ("-- drop it",)
    assert patch_apply.apply(before, parsed) == after


def test_an_added_increment_is_not_mistaken_for_a_file_header() -> None:
    before = ["int i = 0;\n", "return i;\n"]
    after = ["int i = 0;\n", "++i;\n", "return i;\n"]

    parsed = patch_apply.parse(diff_of(before, after, "a.c"))

    assert parsed.added == ("++i;",)
    assert patch_apply.apply(before, parsed) == after


def test_the_parse_reports_what_was_added_and_removed() -> None:
    parsed = patch_apply.parse(diff_of(BEFORE, AFTER))

    assert parsed.old_path == parsed.new_path == "app.py"
    assert parsed.removed == ("    return hashlib.md5(value).hexdigest()",)
    assert parsed.added == ("    return hashlib.sha256(value).hexdigest()",)


# --- refusing -------------------------------------------------------------


def test_a_changed_target_line_is_refused() -> None:
    """Somebody edited the vulnerable line after the fix was proposed."""
    moved = [line.replace("md5(value)", "md5(value, usedforsecurity=False)") for line in BEFORE]

    with pytest.raises(PatchDoesNotApply, match="changed since"):
        patch_apply.apply(moved, patch_apply.parse(diff_of(BEFORE, AFTER)))


def test_a_changed_context_line_is_refused() -> None:
    """Even a line the patch does not touch has to be where it was.

    The context is how a reviewer knew which code they were approving a change
    to. If it has changed, they approved a change to something else.
    """
    moved = [line.replace("def digest(value):", "def digest(value, salt):") for line in BEFORE]

    with pytest.raises(PatchDoesNotApply, match="changed since"):
        patch_apply.apply(moved, patch_apply.parse(diff_of(BEFORE, AFTER)))


def test_code_that_has_only_shifted_down_is_still_refused() -> None:
    """The case `git apply` would accept and this must not.

    The right lines exist, two lines lower. A tool with an offset search finds
    them and applies the patch. Here that is a refusal: no fuzz, no offset, no
    guessing where the author meant.
    """
    shifted = ["# added\n", "# added\n", *BEFORE]

    with pytest.raises(PatchDoesNotApply):
        patch_apply.apply(shifted, patch_apply.parse(diff_of(BEFORE, AFTER)))


def test_a_file_shorter_than_the_hunk_is_refused() -> None:
    with pytest.raises(PatchDoesNotApply):
        patch_apply.apply(BEFORE[:3], patch_apply.parse(diff_of(BEFORE, AFTER)))


def test_a_diff_touching_two_files_is_refused() -> None:
    """One patch, one file — the file its own row names."""
    two = diff_of(BEFORE, AFTER) + diff_of(["x = 1\n"], ["x = 2\n"], "other.py")

    with pytest.raises(PatchDoesNotApply, match="more than one place"):
        patch_apply.parse(two)


def test_a_truncated_diff_is_refused() -> None:
    cut = "\n".join(diff_of(BEFORE, AFTER).split("\n")[:5])

    with pytest.raises(PatchDoesNotApply, match="cut short"):
        patch_apply.parse(cut)


def test_text_that_is_not_a_diff_is_refused() -> None:
    with pytest.raises(PatchDoesNotApply):
        patch_apply.parse("def digest(value):\n    return 1\n    pass\n")


def test_an_empty_diff_is_refused() -> None:
    with pytest.raises(PatchDoesNotApply, match="empty"):
        patch_apply.parse("")


def test_headers_without_any_hunk_are_refused() -> None:
    with pytest.raises(PatchDoesNotApply):
        patch_apply.parse("--- a/app.py\n+++ b/app.py\n\n")


def test_a_header_without_the_expected_prefix_is_refused() -> None:
    odd = diff_of(BEFORE, AFTER).replace("--- a/app.py", "--- /etc/passwd")

    with pytest.raises(PatchDoesNotApply, match="unexpected file header"):
        patch_apply.parse(odd)


def test_a_hunk_that_overruns_its_own_counts_is_refused() -> None:
    """The header says one new line; the body adds three. A diff that disagrees
    with itself is not applied on a best-effort basis."""
    lying = "--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,1 @@\n a\n+b\n+c\n d\n"

    with pytest.raises(PatchDoesNotApply, match="line counts"):
        patch_apply.parse(lying)


def test_hunks_that_overlap_are_refused() -> None:
    """Two hunks claiming the same lines would copy part of the file twice."""
    overlapping = (
        "--- a/app.py\n+++ b/app.py\n@@ -3,2 +3,2 @@\n c\n-d\n+D\n@@ -2,2 +2,2 @@\n b\n-c\n+C\n"
    )

    with pytest.raises(PatchDoesNotApply, match="changed since"):
        patch_apply.apply(["a\n", "b\n", "c\n", "d\n", "e\n"], patch_apply.parse(overlapping))
