"""
Tests for src/utils/file_input.py
"""

import src.utils.file_input as file_input_module
from src.utils.file_input import InvalidEmlPathError, clean_path_input, validate_eml_path


def _make_eml(tmp_path, name="test.eml", content=b"From: a@example.com\r\n\r\nBody\r\n"):
    p = tmp_path / name
    p.write_bytes(content)
    return p


def test_clean_path_input_strips_double_quotes():
    """
    WHAT: A path wrapped in double quotes, as terminals commonly insert
         for a dragged-and-dropped file (especially on Windows).
    WHY: The interactive prompt reads raw input() text with no shell to
         strip quotes for us — this must be handled explicitly.
    EXPECTED: Quotes removed, path returned as-is otherwise.
    """
    assert clean_path_input('"C:\\Users\\madhu\\Downloads\\suspicious email.eml"') == \
        "C:\\Users\\madhu\\Downloads\\suspicious email.eml"


def test_clean_path_input_strips_single_quotes():
    """
    WHAT: A path wrapped in single quotes.
    WHY: Some shells/terminals use single quotes instead of double.
    EXPECTED: Quotes removed.
    """
    assert clean_path_input("'/home/user/file.eml'") == "/home/user/file.eml"


def test_clean_path_input_leaves_unquoted_path_unchanged():
    """
    WHAT: A plain, unquoted path with surrounding whitespace only.
    WHY: Must not mangle a path that was never quoted.
    EXPECTED: Only whitespace is stripped.
    """
    assert clean_path_input("  /home/user/file.eml  ") == "/home/user/file.eml"


def test_valid_eml_path_outside_samples_dir(tmp_path):
    """
    WHAT: A well-formed .eml file in an arbitrary directory, NOT under
         samples/.
    WHY: This is the core new feature — the file must not need to be
         copied into samples/ to be analyzed.
    EXPECTED: validate_eml_path returns a resolved Path with no error.
    """
    p = _make_eml(tmp_path)
    result = validate_eml_path(str(p))
    assert result.name == "test.eml"
    assert result.exists()


def test_path_with_spaces_in_filename(tmp_path):
    """
    WHAT: A filename containing spaces, e.g. "suspicious email.eml" —
         a very common real-world downloaded-attachment filename.
    WHY: Explicitly called out in the feature request as a target scenario.
    EXPECTED: Validates successfully.
    """
    p = _make_eml(tmp_path, name="suspicious email.eml")
    result = validate_eml_path(str(p))
    assert result.name == "suspicious email.eml"


def test_empty_path_raises():
    """
    WHAT: An empty string (e.g. user pressed Enter with no input).
    WHY: Must give a specific, friendly message, not a confusing
         downstream file-not-found error.
    EXPECTED: InvalidEmlPathError mentioning no path was provided.
    """
    try:
        validate_eml_path("")
        assert False, "should have raised"
    except InvalidEmlPathError as e:
        assert "no file path" in str(e).lower()


def test_whitespace_only_path_raises():
    """
    WHAT: A string that is only whitespace.
    WHY: Same as empty-path case — must not be treated as a real path.
    EXPECTED: InvalidEmlPathError mentioning no path was provided.
    """
    try:
        validate_eml_path("   ")
        assert False, "should have raised"
    except InvalidEmlPathError as e:
        assert "no file path" in str(e).lower()


def test_nonexistent_path_raises_with_friendly_message():
    """
    WHAT: A syntactically valid but nonexistent path.
    WHY: Must not let a raw FileNotFoundError/traceback reach the user.
    EXPECTED: InvalidEmlPathError mentioning "not found".
    """
    try:
        validate_eml_path("/definitely/does/not/exist/file.eml")
        assert False, "should have raised"
    except InvalidEmlPathError as e:
        assert "not found" in str(e).lower()


def test_directory_instead_of_file_raises(tmp_path):
    """
    WHAT: A path that exists but is a directory, not a file.
    WHY: A user might accidentally point this at a folder of emails
         instead of one specific file.
    EXPECTED: InvalidEmlPathError mentioning it's not a file.
    """
    try:
        validate_eml_path(str(tmp_path))
        assert False, "should have raised"
    except InvalidEmlPathError as e:
        assert "not a file" in str(e).lower()


def test_wrong_extension_raises(tmp_path):
    """
    WHAT: A real, readable file that is NOT a .eml (e.g. .txt, .msg).
    WHY: Per spec, only .eml files should be accepted.
    EXPECTED: InvalidEmlPathError naming the actual extension found.
    """
    p = tmp_path / "notes.txt"
    p.write_text("hello")
    try:
        validate_eml_path(str(p))
        assert False, "should have raised"
    except InvalidEmlPathError as e:
        assert ".txt" in str(e)


def test_no_extension_raises(tmp_path):
    """
    WHAT: A file with no extension at all.
    WHY: Edge case of the extension check — must not crash on an empty suffix.
    EXPECTED: InvalidEmlPathError with a readable "(no extension)" message.
    """
    p = tmp_path / "noextension"
    p.write_text("hello")
    try:
        validate_eml_path(str(p))
        assert False, "should have raised"
    except InvalidEmlPathError as e:
        assert "no extension" in str(e).lower()


def test_extension_check_is_case_insensitive(tmp_path):
    """
    WHAT: A file with a uppercase '.EML' extension.
    WHY: Windows filesystems and some mail exports use uppercase extensions.
    EXPECTED: Validates successfully — no false rejection.
    """
    p = _make_eml(tmp_path, name="test.EML")
    result = validate_eml_path(str(p))
    assert result.suffix == ".EML"


def test_zero_byte_file_is_not_rejected_here(tmp_path):
    """
    WHAT: A genuinely empty (0-byte) .eml file.
    WHY: The existing pipeline (email_parser.py) already handles empty
         files gracefully with a warning rather than crashing — this
         validation layer must not be STRICTER than the pipeline it
         feeds, or it would block a scenario the pipeline already
         supports and is tested for.
    EXPECTED: validate_eml_path does NOT raise for a 0-byte file.
    """
    p = _make_eml(tmp_path, content=b"")
    result = validate_eml_path(str(p))
    assert result.exists()


def test_oversized_file_raises(tmp_path, monkeypatch):
    """
    WHAT: A file larger than the configured maximum.
    WHY: Guards against pointing the tool at an obviously-wrong huge file.
         Uses a monkeypatched, tiny limit rather than writing a real
         25 MB file, to keep the test fast.
    EXPECTED: InvalidEmlPathError mentioning the file is too large.
    """
    monkeypatch.setattr(file_input_module, "MAX_EML_SIZE_BYTES", 10)
    p = _make_eml(tmp_path, content=b"x" * 100)
    try:
        validate_eml_path(str(p))
        assert False, "should have raised"
    except InvalidEmlPathError as e:
        assert "too large" in str(e).lower()


def test_quoted_path_from_drag_and_drop_validates_successfully(tmp_path):
    """
    WHAT: A path passed exactly as a terminal would insert it after a
         drag-and-drop, wrapped in double quotes.
    WHY: End-to-end check that clean_path_input is actually applied
         inside validate_eml_path, not just tested in isolation.
    EXPECTED: Validates successfully despite the surrounding quotes.
    """
    p = _make_eml(tmp_path, name="dropped.eml")
    quoted = f'"{p}"'
    result = validate_eml_path(quoted)
    assert result.name == "dropped.eml"


def test_does_not_modify_the_original_file(tmp_path):
    """
    WHAT: Validating a file, then re-reading its content afterward.
    WHY: Per spec, the tool must never move, copy, modify, or delete the
         original email during validation.
    EXPECTED: File content is byte-identical before and after validation.
    """
    content = b"From: a@example.com\r\n\r\nOriginal content.\r\n"
    p = _make_eml(tmp_path, content=content)
    validate_eml_path(str(p))
    assert p.read_bytes() == content