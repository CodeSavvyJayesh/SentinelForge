"""Reading and splicing the region a proposal may change.

The interesting tests here are not about reading a file. They are about the
three ways a naive implementation quietly corrupts somebody's code: reading
outside the workspace, converting every line ending in the file, and adding or
removing a final newline nobody asked for.
"""

from pathlib import Path

import pytest

from app.patching.region import (
    MAX_LINE_CHARS,
    REPLACE_END,
    REPLACE_START,
    RegionError,
    read_region,
    splice,
)

SOURCE = """\
import hashlib


def digest(value):
    return hashlib.md5(value).hexdigest()


def other():
    return 1
"""


def write(root: Path, name: str = "app.py", text: str = SOURCE) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_the_replaceable_span_is_the_findings_own_lines(tmp_path: Path) -> None:
    """Context is shown, never replaced.

    This is the correction to the first version of the phase, and it was found
    in the running application rather than here: asked to replace a whole
    window, a real model returns only the changed line, which then reads as a
    proposal to delete the rest of the window. The deletion check threw away a
    correct fix. The model is now asked the question it can answer.
    """
    write(tmp_path)

    region = read_region(tmp_path, "app.py", 5, 5, context=2)

    assert region.first_line == 5
    assert region.last_line == 5
    assert region.lines == ["    return hashlib.md5(value).hexdigest()\n"]
    assert region.window_first_line == 3
    assert region.window_last_line == 7
    assert len(region.context_before) == 2
    assert len(region.context_after) == 2


def test_context_is_clipped_at_the_edges_of_the_file(tmp_path: Path) -> None:
    write(tmp_path)

    region = read_region(tmp_path, "app.py", 1, 1, context=50)

    assert region.window_first_line == 1
    assert region.window_last_line == len(SOURCE.splitlines())
    assert region.context_before == []


def test_the_prompt_view_fences_off_the_replaceable_lines(tmp_path: Path) -> None:
    """The markers are how the model knows which lines it may rewrite."""
    write(tmp_path)

    numbered = read_region(tmp_path, "app.py", 5, 5, context=2).numbered()

    lines = numbered.splitlines()
    start = next(i for i, line in enumerate(lines) if REPLACE_START in line)
    end = next(i for i, line in enumerate(lines) if REPLACE_END in line)
    fenced = lines[start + 1 : end]
    assert len(fenced) == 1
    assert "hashlib.md5" in fenced[0]
    # And the context is outside the fence, where it cannot be mistaken for
    # something to hand back.
    assert any("def digest" in line for line in lines[:start])


def test_a_multi_line_finding_keeps_all_its_lines_replaceable(tmp_path: Path) -> None:
    write(tmp_path)

    region = read_region(tmp_path, "app.py", 4, 5, context=1)

    assert region.first_line == 4
    assert region.last_line == 5
    assert len(region.lines) == 2


def test_the_numbered_view_uses_real_file_line_numbers(tmp_path: Path) -> None:
    """The model is shown file line numbers, not 1..n.

    If it were shown 1..n it could not talk about the finding's line, which the
    prompt names by its number in the file.
    """
    write(tmp_path)

    numbered = read_region(tmp_path, "app.py", 5, 5, context=2).numbered()

    first = numbered.splitlines()[0]
    assert first.strip().startswith("3 |")
    assert any(line.strip().startswith("5 |") for line in numbered.splitlines())


# --- refusals -------------------------------------------------------------


def test_a_path_escaping_the_workspace_is_refused(tmp_path: Path) -> None:
    """``file_path`` comes from a row built out of somebody else's upload.

    A stored ``../secret.txt`` must not be read and handed to a model. This is
    the same containment check Phase 4 applies to archive members, and it is
    repeated here because this is a second place a stored path is resolved.
    """
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (tmp_path / "secret.txt").write_text("PRIVATE", encoding="utf-8")

    with pytest.raises(RegionError, match="outside its repository workspace"):
        read_region(workspace, "../secret.txt", 1, 1)


def test_a_symlink_out_of_the_workspace_is_refused(tmp_path: Path) -> None:
    """Resolution happens before the check, so a link cannot smuggle a path."""
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (tmp_path / "secret.txt").write_text("PRIVATE", encoding="utf-8")
    try:
        (workspace / "link.py").symlink_to(tmp_path / "secret.txt")
    except (OSError, NotImplementedError):  # pragma: no cover - Windows without privilege
        pytest.skip("symlinks not permitted here")

    with pytest.raises(RegionError, match="outside its repository workspace"):
        read_region(workspace, "link.py", 1, 1)


def test_a_line_past_the_end_of_the_file_says_the_copy_has_changed(tmp_path: Path) -> None:
    write(tmp_path)

    with pytest.raises(RegionError, match="Scan again"):
        read_region(tmp_path, "app.py", 900, 900)


def test_a_missing_file_is_refused(tmp_path: Path) -> None:
    with pytest.raises(RegionError, match="no longer in the stored copy"):
        read_region(tmp_path, "gone.py", 1, 1)


def test_a_minified_file_is_refused(tmp_path: Path) -> None:
    """A patch to a 40,000-character line is unreviewable even if it is right."""
    write(tmp_path, "bundle.js", "x" * (MAX_LINE_CHARS + 1) + "\n")

    with pytest.raises(RegionError, match="lines too long"):
        read_region(tmp_path, "bundle.js", 1, 1)


# --- splicing -------------------------------------------------------------


def test_splice_replaces_exactly_the_region(tmp_path: Path) -> None:
    write(tmp_path)
    region = read_region(tmp_path, "app.py", 5, 5, context=0)

    after = splice(region, "    return hashlib.sha256(value).hexdigest()\n")

    assert "".join(after) == SOURCE.replace("hashlib.md5(value)", "hashlib.sha256(value)")


def test_a_crlf_file_keeps_its_line_endings(tmp_path: Path) -> None:
    """A model answering with ``\\n`` must not convert the whole file.

    It would apply — and the diff would be every line in the file, which no
    reviewer can read. The endings come from the file, never from the model.
    """
    crlf = SOURCE.replace("\n", "\r\n")
    path = tmp_path / "app.py"
    path.write_bytes(crlf.encode())
    region = read_region(tmp_path, "app.py", 5, 5, context=0)

    after = splice(region, "    return hashlib.sha256(value).hexdigest()")

    assert all(line.endswith("\r\n") for line in after)
    assert "".join(after) == crlf.replace("hashlib.md5(value)", "hashlib.sha256(value)")


def test_a_file_without_a_final_newline_does_not_gain_one(tmp_path: Path) -> None:
    """Otherwise the diff reports a change to the last line nobody edited."""
    text = "a = 1\nb = 2"
    write(tmp_path, "tail.py", text)
    region = read_region(tmp_path, "tail.py", 2, 2, context=0)

    after = splice(region, "b = 3")

    assert "".join(after) == "a = 1\nb = 3"


def test_a_file_with_a_final_newline_keeps_it(tmp_path: Path) -> None:
    write(tmp_path, "tail.py", "a = 1\nb = 2\n")
    region = read_region(tmp_path, "tail.py", 2, 2, context=0)

    after = splice(region, "b = 3")

    assert "".join(after) == "a = 1\nb = 3\n"


def test_a_multi_line_replacement_expands_the_file(tmp_path: Path) -> None:
    write(tmp_path)
    region = read_region(tmp_path, "app.py", 5, 5, context=0)

    after = splice(region, "    digest = hashlib.sha256(value)\n    return digest.hexdigest()")

    assert len(after) == len(SOURCE.splitlines()) + 1
    assert "    digest = hashlib.sha256(value)\n" in after
    assert "    return digest.hexdigest()\n" in after


# --- indentation ----------------------------------------------------------


def test_a_replacement_that_lost_its_indentation_is_put_back(tmp_path: Path) -> None:
    """The defect the first Java proposal exhibited.

    Asked to fix a line eight spaces deep, the model returned the corrected
    line against the margin. In Java that is cosmetic; in Python the file stops
    parsing and a correct fix gets refused for "not parsing as Python".
    """
    from app.patching.region import reindent

    original = ["        return md5(value)\n"]

    fixed, changed = reindent("return sha256(value)", original)

    assert fixed == "        return sha256(value)"
    assert changed is True


def test_relative_indentation_inside_the_replacement_survives(tmp_path: Path) -> None:
    """A returned if/else keeps its shape — the whole block shifts together."""
    from app.patching.region import reindent

    original = ["    value = compute()\n"]

    fixed, changed = reindent("if x:\n    a()\nelse:\n    b()", original)

    assert fixed == "    if x:\n        a()\n    else:\n        b()"
    assert changed is True


def test_a_correctly_indented_replacement_is_left_alone(tmp_path: Path) -> None:
    from app.patching.region import reindent

    original = ["    return md5(value)\n"]

    fixed, changed = reindent("    return sha256(value)", original)

    assert fixed == "    return sha256(value)"
    assert changed is False


def test_blank_lines_are_never_given_indentation(tmp_path: Path) -> None:
    """Trailing whitespace on an empty line is noise in the diff, and some
    linters fail on it."""
    from app.patching.region import reindent

    fixed, _ = reindent("a()\n\nb()", ["    original()\n"])

    assert fixed == "    a()\n\n    b()"


def test_splicing_a_dedented_python_fix_still_parses(tmp_path: Path) -> None:
    """End to end for the case that matters: without re-indentation this file
    would not compile, and the syntax check would throw the fix away."""
    import ast

    from app.patching.region import reindent

    write(tmp_path)
    region = read_region(tmp_path, "app.py", 5, 5, context=0)

    replacement, changed = reindent("return hashlib.sha256(value).hexdigest()", region.lines)
    after = splice(region, replacement)

    assert changed is True
    ast.parse("".join(after))  # would raise before the fix
