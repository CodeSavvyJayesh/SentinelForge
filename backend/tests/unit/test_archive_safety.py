"""Archive extraction under attack.

Each test here is a real technique, not a hypothetical: zip slip (CVE-2018-1002200
and dozens like it), symlink escape, zip bombs, and lying headers.
"""

import zipfile
from pathlib import Path

import pytest

from app.core.config import Settings, get_settings
from app.ingestion.archive import (
    ExtractionResult,
    detect_root_prefix,
    extract_archive,
    safe_member_path,
)
from app.ingestion.limits import (
    ArchiveExpandsTooMuchError,
    ArchiveInvalidError,
    ArchiveTooManyFilesError,
    ArchiveUnsafeError,
)


@pytest.fixture
def settings() -> Settings:
    return get_settings()


def build_zip(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return path


# --- path traversal -------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "../escaped.py",
        "../../etc/passwd",
        "app/../../escaped.py",
        "/etc/passwd",
        "..\\windows\\system32\\evil.dll",
        "C:/Windows/evil.dll",
    ],
)
def test_traversal_paths_are_refused(tmp_path: Path, settings: Settings, name: str) -> None:
    archive = build_zip(tmp_path / "evil.zip", {name: b"payload"})
    destination = tmp_path / "out"
    destination.mkdir()

    with pytest.raises(ArchiveUnsafeError):
        extract_archive(archive, destination, settings)

    # Nothing escaped: the parent directory is untouched apart from our inputs.
    assert not (tmp_path / "escaped.py").exists()
    assert not (tmp_path.parent / "escaped.py").exists()


def test_safe_member_path_accepts_ordinary_names(tmp_path: Path) -> None:
    destination = tmp_path / "out"
    destination.mkdir()
    assert safe_member_path(destination, "src/app/main.py") == destination / "src/app/main.py"


def test_a_name_that_only_looks_like_traversal_is_allowed(tmp_path: Path) -> None:
    # "..foo" is a legitimate filename; only a real ".." path part escapes.
    destination = tmp_path / "out"
    destination.mkdir()
    assert safe_member_path(destination, "..foo/bar.py").is_relative_to(destination)


# --- symlinks and special files -------------------------------------------


def test_symlink_entries_are_refused(tmp_path: Path, settings: Settings) -> None:
    archive_path = tmp_path / "link.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        info = zipfile.ZipInfo("secrets")
        info.external_attr = 0o120777 << 16  # S_IFLNK
        archive.writestr(info, "/etc/passwd")

    destination = tmp_path / "out"
    destination.mkdir()
    with pytest.raises(ArchiveUnsafeError, match="symbolic link"):
        extract_archive(archive_path, destination, settings)
    assert not (destination / "secrets").exists()


def test_special_files_are_refused(tmp_path: Path, settings: Settings) -> None:
    archive_path = tmp_path / "dev.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        info = zipfile.ZipInfo("fifo")
        info.external_attr = 0o010644 << 16  # S_IFIFO
        archive.writestr(info, "")

    destination = tmp_path / "out"
    destination.mkdir()
    with pytest.raises(ArchiveUnsafeError, match="special file"):
        extract_archive(archive_path, destination, settings)


# --- zip bombs ------------------------------------------------------------


def test_a_high_compression_ratio_is_refused(tmp_path: Path, settings: Settings) -> None:
    # 2 MB of zeros compresses to a couple of kilobytes: ratio far over 100.
    archive = build_zip(tmp_path / "bomb.zip", {"bomb.txt": b"\0" * (2 * 1024 * 1024)})
    destination = tmp_path / "out"
    destination.mkdir()

    with pytest.raises(ArchiveExpandsTooMuchError):
        extract_archive(archive, destination, settings)


def test_total_expansion_over_the_budget_is_refused(tmp_path: Path, settings: Settings) -> None:
    # Random-ish data does not compress, so the ratio check passes and the
    # *total size* check is what has to stop this.
    import secrets

    blob = secrets.token_bytes(150 * 1024)
    entries = {f"file{index}.bin": blob for index in range(40)}  # ~6 MB > 4 MB budget
    archive = build_zip(tmp_path / "big.zip", entries)
    destination = tmp_path / "out"
    destination.mkdir()

    with pytest.raises(ArchiveExpandsTooMuchError):
        extract_archive(archive, destination, settings)


def test_a_lying_header_cannot_write_an_oversized_file(
    tmp_path: Path, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``file_size`` comes from the archive, so it is attacker-controlled.

    Here every header is made to claim one byte while the entry really holds
    far more than the per-file limit. The pre-check is therefore useless and
    only the byte counter running during the write can keep the file off disk.

    (Python's ``zipfile`` also stops reading at the declared size, so in
    practice both defences have to fail before anything oversized lands. The
    counter is the one that does not depend on the standard library's
    behaviour staying the same.)
    """
    payload = b"A" * (settings.MAX_FILE_BYTES + 50 * 1024)
    archive_path = build_zip(tmp_path / "liar.zip", {"liar.txt": payload})

    honest_infolist = zipfile.ZipFile.infolist

    def lying_infolist(self: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
        infos = honest_infolist(self)
        for info in infos:
            info.file_size = 1
        return infos

    monkeypatch.setattr(zipfile.ZipFile, "infolist", lying_infolist)

    destination = tmp_path / "out"
    destination.mkdir()
    try:
        result = extract_archive(archive_path, destination, settings)
    except ArchiveInvalidError:
        # zipfile notices the CRC no longer matches and the archive is refused
        # outright. Also a correct outcome, and still no oversized file.
        result = None

    written = destination / "liar.txt"
    assert not written.exists() or written.stat().st_size <= settings.MAX_FILE_BYTES
    if result is not None:
        assert result.total_bytes <= settings.MAX_UNCOMPRESSED_BYTES


# --- volume limits --------------------------------------------------------


def test_too_many_files_is_refused(tmp_path: Path, settings: Settings) -> None:
    entries = {f"src/file{index}.py": b"x = 1\n" for index in range(settings.MAX_FILES + 5)}
    archive = build_zip(tmp_path / "many.zip", entries)
    destination = tmp_path / "out"
    destination.mkdir()

    with pytest.raises(ArchiveTooManyFilesError):
        extract_archive(archive, destination, settings)


def test_an_oversized_file_is_skipped_not_fatal(tmp_path: Path, settings: Settings) -> None:
    import secrets

    entries = {
        "huge.bin": secrets.token_bytes(settings.MAX_FILE_BYTES + 1024),
        "small.py": b"print('hello')\n",
    }
    archive = build_zip(tmp_path / "mixed.zip", entries)
    destination = tmp_path / "out"
    destination.mkdir()

    result = extract_archive(archive, destination, settings)

    assert result.file_count == 1
    assert (destination / "small.py").exists()
    assert not (destination / "huge.bin").exists()
    assert "huge.bin" in result.skipped_paths


def test_ignored_directories_are_not_extracted(tmp_path: Path, settings: Settings) -> None:
    archive = build_zip(
        tmp_path / "vendored.zip",
        {
            "src/main.py": b"print(1)\n",
            "node_modules/left-pad/index.js": b"module.exports = 1\n",
            ".git/config": b"[core]\n",
            "__pycache__/main.cpython-311.pyc": b"\x00\x01",
        },
    )
    destination = tmp_path / "out"
    destination.mkdir()

    result = extract_archive(archive, destination, settings)

    assert result.file_count == 1
    assert not (destination / "node_modules").exists()
    assert not (destination / ".git").exists()


# --- ordinary behaviour ---------------------------------------------------


def test_a_normal_archive_extracts_with_plain_permissions(
    tmp_path: Path, settings: Settings
) -> None:
    archive_path = tmp_path / "ok.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        info = zipfile.ZipInfo("run.sh")
        info.external_attr = 0o100777 << 16  # world-writable and executable
        archive.writestr(info, "echo hi\n")
        archive.writestr("app/main.py", "print('hi')\n")

    destination = tmp_path / "out"
    destination.mkdir()
    result = extract_archive(archive_path, destination, settings)

    assert result.file_count == 2
    assert (destination / "app/main.py").read_text() == "print('hi')\n"
    mode = (destination / "run.sh").stat().st_mode & 0o777
    assert mode == 0o644, "extracted files must never keep an execute bit"


def test_re_extracting_over_an_executable_file_resets_its_permissions(
    tmp_path: Path, settings: Settings
) -> None:
    """Opening a file for writing keeps the permissions it already had.

    So a workspace that already contains ``run.sh`` with the execute bit set
    (a previous extraction, or a directory reused after a crash) would keep it
    unless the mode is reset explicitly.
    """
    archive = build_zip(tmp_path / "again.zip", {"run.sh": b"echo hi\n"})
    destination = tmp_path / "out"
    destination.mkdir()
    stale = destination / "run.sh"
    stale.write_text("old\n")
    stale.chmod(0o777)

    extract_archive(archive, destination, settings)

    assert stale.stat().st_mode & 0o777 == 0o644
    assert stale.stat().st_mode & 0o111 == 0, "no extracted file may be executable"


def test_a_corrupt_file_is_a_clean_error(tmp_path: Path, settings: Settings) -> None:
    broken = tmp_path / "not-a-zip.zip"
    broken.write_bytes(b"this is not a zip file at all")
    destination = tmp_path / "out"
    destination.mkdir()

    with pytest.raises(ArchiveInvalidError):
        extract_archive(broken, destination, settings)


def test_detect_root_prefix() -> None:
    assert detect_root_prefix(["flask-main/setup.py", "flask-main/src/app.py"]) == "flask-main"
    assert detect_root_prefix(["setup.py", "src/app.py"]) is None
    assert detect_root_prefix(["only-a-file.py"]) is None


def test_extraction_result_defaults() -> None:
    result = ExtractionResult()
    assert (result.file_count, result.total_bytes, result.skipped_paths) == (0, 0, [])
