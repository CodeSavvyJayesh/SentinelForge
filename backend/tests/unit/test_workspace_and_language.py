"""Workspace isolation and language detection."""

import os
from pathlib import Path

import pytest

from app.core.config import Settings, get_settings
from app.ingestion.language import classify, summarise_tree
from app.ingestion.workspace import WorkspaceManager


@pytest.fixture
def manager(tmp_path: Path) -> WorkspaceManager:
    settings: Settings = get_settings().model_copy(update={"WORKSPACE_ROOT": str(tmp_path / "ws")})
    return WorkspaceManager(settings)


# --- workspaces -----------------------------------------------------------


def test_each_repository_gets_its_own_directory(manager: WorkspaceManager) -> None:
    first, first_relative = manager.create(project_id=1, repository_id=1)
    second, second_relative = manager.create(project_id=1, repository_id=2)

    assert first.is_dir() and second.is_dir()
    assert first != second
    assert first_relative != second_relative
    assert not Path(first_relative).is_absolute(), "the stored path must be relative"


def test_two_repositories_with_the_same_id_do_not_collide(manager: WorkspaceManager) -> None:
    """The random suffix means a re-ingest never lands in a stale directory."""
    first, _ = manager.create(project_id=7, repository_id=7)
    second, _ = manager.create(project_id=7, repository_id=7)
    assert first != second


@pytest.mark.parametrize(
    "relative",
    ["../outside", "../../etc", "project-1/../../../tmp", "/etc"],
)
def test_paths_outside_the_root_are_refused(manager: WorkspaceManager, relative: str) -> None:
    with pytest.raises(ValueError, match="outside the workspace root"):
        manager.absolute(relative)
    with pytest.raises(ValueError, match="outside the workspace root"):
        manager.remove(relative)


def test_removing_deletes_only_that_workspace(manager: WorkspaceManager) -> None:
    keep, keep_relative = manager.create(project_id=1, repository_id=1)
    drop, drop_relative = manager.create(project_id=1, repository_id=2)
    (drop / "file.py").write_text("x = 1\n")

    manager.remove(drop_relative)

    assert not drop.exists()
    assert keep.exists()
    assert manager.absolute(keep_relative) == keep


def test_removing_a_missing_workspace_is_not_an_error(manager: WorkspaceManager) -> None:
    manager.remove("project-1/repo-does-not-exist")
    manager.remove(None)


# --- language detection ---------------------------------------------------


@pytest.mark.parametrize(
    ("filename", "language"),
    [
        ("main.py", "Python"),
        ("App.tsx", "TypeScript"),
        ("index.js", "JavaScript"),
        ("Main.java", "Java"),
        ("server.go", "Go"),
        ("Dockerfile", "Dockerfile"),
        ("Dockerfile.prod", "Dockerfile"),
        ("Makefile", "Make"),
        ("schema.sql", "SQL"),
        ("notes.unknownext", "Other"),
        ("LICENSE", "Other"),
    ],
)
def test_classify(filename: str, language: str) -> None:
    assert classify(Path(filename)) == language


def test_the_primary_language_is_the_one_with_the_most_code(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src/main.py").write_text("x = 1\n" * 500)
    (tmp_path / "src/helper.py").write_text("y = 2\n" * 100)
    (tmp_path / "src/app.ts").write_text("const a = 1;\n" * 20)

    summary = summarise_tree(tmp_path)

    assert summary.primary_language == "Python"
    assert summary.file_count == 3
    assert summary.breakdown is not None
    assert list(summary.breakdown)[0] == "Python"  # ordered biggest first
    assert summary.total_bytes == sum(
        path.stat().st_size for path in tmp_path.rglob("*") if path.is_file()
    )


def test_configuration_and_prose_never_win(tmp_path: Path) -> None:
    """A repository is not "a YAML project" because its CI config is long."""
    (tmp_path / "ci.yml").write_text("steps:\n" * 2000)
    (tmp_path / "README.md").write_text("# docs\n" * 2000)
    (tmp_path / "app.py").write_text("print(1)\n")

    summary = summarise_tree(tmp_path)

    assert summary.primary_language == "Python"
    assert summary.breakdown is not None
    assert "YAML" in summary.breakdown  # still reported, just not primary


def test_a_tree_with_no_recognised_code_reports_nothing(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("hello")
    (tmp_path / "data.bin").write_bytes(b"\x00\x01")

    summary = summarise_tree(tmp_path)

    assert summary.file_count == 2
    assert summary.primary_language is None, "a language must never be guessed"


def test_an_empty_tree_is_empty(tmp_path: Path) -> None:
    summary = summarise_tree(tmp_path)
    assert summary.file_count == 0
    assert summary.total_bytes == 0
    assert summary.breakdown is None


def test_ignored_directories_are_not_counted(tmp_path: Path) -> None:
    (tmp_path / "node_modules/left-pad").mkdir(parents=True)
    (tmp_path / "node_modules/left-pad/index.js").write_text("module.exports = 1\n" * 1000)
    (tmp_path / "app.py").write_text("print(1)\n")

    summary = summarise_tree(tmp_path)

    assert summary.file_count == 1
    assert summary.primary_language == "Python"


def test_symlinks_are_not_counted_or_followed(tmp_path: Path) -> None:
    """A link is not a file in the repository; it is a file somewhere else.

    Counting ``passwd.py -> /etc/passwd`` would add the server's own bytes to
    the totals, and a later phase would happily read and analyse them.
    """
    (tmp_path / "app.py").write_text("print(1)\n")
    os.symlink("/etc/passwd", tmp_path / "passwd.py")  # a link to a FILE
    os.symlink("/etc", tmp_path / "escape")  # and one to a DIRECTORY

    summary = summarise_tree(tmp_path)

    assert summary.file_count == 1, "only the real file is counted"
    assert summary.total_bytes == (tmp_path / "app.py").stat().st_size
    assert summary.primary_language == "Python"
