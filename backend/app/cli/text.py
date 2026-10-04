"""Making text from somebody else's repository safe to print."""

import unicodedata


def plain(value: object) -> str:
    """Text from a scanned repository, made safe to print.

    A file can be *named* with an escape sequence in it, and a terminal will
    obey one: move the cursor, recolour the screen, rewrite the line above. A
    build log has a second problem — a line that begins with ``::`` is a
    command to the GitHub Actions runner. So every control and formatting
    character, including the line breaks that would let text start a line of
    its own, is replaced before anything is written.
    """
    return "".join(
        "?" if unicodedata.category(character) in {"Cc", "Cf", "Zl", "Zp"} else character
        for character in str(value)
    )


__all__ = ["plain"]
