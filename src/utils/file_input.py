"""
file_input.py

Validates a user-supplied path to a .eml file located ANYWHERE on disk —
not just under samples/. Kept as a standalone module (rather than inline
in main.py) so it's unit-testable without mocking input() or argparse.

Never moves, copies, modifies, deletes, opens for writing, or executes
the target file — only stats it and reads a single byte to confirm
readability. The actual email content is parsed later, unchanged, by the
existing src/parser/email_parser.py.
"""

from __future__ import annotations

from pathlib import Path

# 25 MB is generous for an email with attachments while still catching an
# obviously-wrong file (e.g. someone accidentally pointing this at a large
# archive or disk image instead of a single .eml export).
MAX_EML_SIZE_BYTES = 25 * 1024 * 1024


class InvalidEmlPathError(Exception):
    """
    Raised with a short, user-friendly message when a supplied path can't
    be analyzed. main.py catches this and prints the message directly
    instead of letting a traceback reach the user.
    """


def clean_path_input(raw: str) -> str:
    """
    Strip whitespace and a single matching pair of leading/trailing quote
    characters. Terminals commonly wrap a path in quotes when a file is
    dragged-and-dropped or pasted — especially on Windows, e.g.:

        '"C:\\Users\\madhu\\Downloads\\suspicious email.eml"'

    becomes:

        'C:\\Users\\madhu\\Downloads\\suspicious email.eml'

    A CLI argument passed via the shell is normally already unquoted by
    the shell itself, but this is applied uniformly (idempotently) to
    both the CLI-argument path and the interactive-prompt path, since it
    never harms an already-clean path.
    """
    cleaned = raw.strip()
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in ("'", '"'):
        cleaned = cleaned[1:-1]
    return cleaned.strip()


def validate_eml_path(raw_path: str) -> Path:
    """
    Validates a user-supplied path and returns a resolved Path on success.

    Checks, in order: non-empty input, existence, is-a-file (not a
    directory), .eml extension, size within MAX_EML_SIZE_BYTES,
    readability. Raises InvalidEmlPathError with a specific, friendly
    message on the first check that fails.

    Deliberately does NOT reject a zero-byte file here — the existing
    pipeline (src/parser/email_parser.py) already handles empty .eml
    files gracefully with a warning rather than a crash, and that
    behavior is relied on elsewhere (see
    tests/test_email_parser.py::test_empty_email_does_not_crash).
    Duplicating that rejection here would make this validation stricter
    than the pipeline it feeds, for no benefit.
    """
    if raw_path is None or not raw_path.strip():
        raise InvalidEmlPathError("No file path provided.")

    cleaned = clean_path_input(raw_path)
    if not cleaned:
        raise InvalidEmlPathError("No file path provided.")

    path = Path(cleaned).expanduser()

    if not path.exists():
        raise InvalidEmlPathError(f"File not found: {cleaned}")

    if not path.is_file():
        raise InvalidEmlPathError(f"Not a file (is it a directory?): {cleaned}")

    if path.suffix.lower() != ".eml":
        shown_suffix = path.suffix or "(no extension)"
        raise InvalidEmlPathError(
            f"Expected a .eml file, got '{shown_suffix}': {cleaned}"
        )

    try:
        size = path.stat().st_size
    except OSError as exc:
        raise InvalidEmlPathError(f"Could not read file metadata: {exc}") from exc

    if size > MAX_EML_SIZE_BYTES:
        size_mb = size / (1024 * 1024)
        max_mb = MAX_EML_SIZE_BYTES / (1024 * 1024)
        raise InvalidEmlPathError(
            f"File is too large ({size_mb:.1f} MB, max {max_mb:.0f} MB): {cleaned}"
        )

    try:
        with open(path, "rb") as f:
            f.read(1)
    except OSError as exc:
        raise InvalidEmlPathError(f"File is not readable: {exc}") from exc

    return path