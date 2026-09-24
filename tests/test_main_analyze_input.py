"""
Integration tests for the new input-handling behavior in src/main.py.

These call run_analyze() directly (not via subprocess) so they run fast
and don't depend on the installed console script. Report output is
always redirected to tmp_path so these tests never write into the
repo's real reports/ directory.
"""

import io
from contextlib import redirect_stdout
from unittest.mock import patch

from src.main import run_analyze

_SAMPLE_EML = (
    "From: attacker@example.test\r\n"
    "To: victim@example.com\r\n"
    "Reply-To: other@example.test\r\n"
    "Subject: Test\r\n"
    "Content-Type: text/plain; charset=\"utf-8\"\r\n"
    "Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail\r\n\r\n"
    "Hello.\r\n"
)


def _write_sample(path, name="sample.eml"):
    p = path / name
    p.write_text(_SAMPLE_EML)
    return p


def test_analyze_file_outside_samples_directory_succeeds(tmp_path):
    """
    WHAT: A .eml file in a temp directory completely unrelated to the
         project's samples/ folder, passed directly to run_analyze.
    WHY: This is the core new feature — the file must analyze
         successfully without being copied into samples/.
    EXPECTED: Returns 0 (success); a report is written to the given
              output directory.
    """
    eml = _write_sample(tmp_path)
    output_dir = tmp_path / "out"
    buf = io.StringIO()
    with redirect_stdout(buf):
        result = run_analyze(str(eml), verbose=False, output_dir=str(output_dir))

    assert result == 0
    assert any(output_dir.glob("*.md"))
    assert "Source File:" in buf.getvalue()
    assert str(eml) in buf.getvalue()


def test_analyze_file_with_space_in_filename(tmp_path):
    """
    WHAT: A filename containing a space, e.g. a realistic downloaded
         attachment name like "suspicious email.eml".
    WHY: Explicitly called out in the feature request as a target scenario.
    EXPECTED: Returns 0; no path-splitting errors.
    """
    eml = _write_sample(tmp_path, name="suspicious email.eml")
    output_dir = tmp_path / "out"
    buf = io.StringIO()
    with redirect_stdout(buf):
        result = run_analyze(str(eml), verbose=False, output_dir=str(output_dir))
    assert result == 0


def test_nonexistent_path_returns_1_without_raising(tmp_path):
    """
    WHAT: A path that doesn't exist, passed directly as eml_path.
    WHY: Must fail gracefully with a friendly message and exit code 1 —
         never propagate an unhandled exception up through run_analyze.
    EXPECTED: Returns 1; no exception raised; friendly message printed.
    """
    output_dir = tmp_path / "out"
    buf = io.StringIO()
    with redirect_stdout(buf):
        result = run_analyze(str(tmp_path / "nope.eml"), verbose=False, output_dir=str(output_dir))

    assert result == 1
    assert "not found" in buf.getvalue().lower()
    assert "Traceback" not in buf.getvalue()


def test_wrong_extension_returns_1_without_raising(tmp_path):
    """
    WHAT: A real, existing file that isn't a .eml.
    WHY: Same graceful-failure guarantee for a different validation branch.
    EXPECTED: Returns 1; friendly message naming the wrong extension.
    """
    bad_file = tmp_path / "notes.txt"
    bad_file.write_text("not an email")
    output_dir = tmp_path / "out"
    buf = io.StringIO()
    with redirect_stdout(buf):
        result = run_analyze(str(bad_file), verbose=False, output_dir=str(output_dir))

    assert result == 1
    assert ".txt" in buf.getvalue()


def test_interactive_mode_accepts_valid_path(tmp_path):
    """
    WHAT: eml_path=None (simulating no CLI argument given), with a valid
         path supplied via the mocked interactive prompt.
    WHY: Core new feature — interactive mode must feed into the exact
         same pipeline as the direct-argument path.
    EXPECTED: Returns 0; the analysis completes successfully.
    """
    eml = _write_sample(tmp_path)
    output_dir = tmp_path / "out"
    buf = io.StringIO()
    with patch("builtins.input", return_value=str(eml)):
        with redirect_stdout(buf):
            result = run_analyze(None, verbose=False, output_dir=str(output_dir))

    assert result == 0
    assert "Enter the path to your .eml file" in buf.getvalue()


def test_interactive_mode_retries_after_invalid_input(tmp_path):
    """
    WHAT: eml_path=None, with the mocked prompt first returning an
         invalid path, then a valid one on the second call.
    WHY: The interactive loop must recover from a bad entry rather than
         crashing or exiting after one failed attempt.
    EXPECTED: Returns 0 after the second, valid input; the friendly
              retry message appears in the output.
    """
    eml = _write_sample(tmp_path)
    output_dir = tmp_path / "out"
    buf = io.StringIO()
    responses = iter(["/does/not/exist.eml", str(eml)])
    with patch("builtins.input", side_effect=lambda _: next(responses)):
        with redirect_stdout(buf):
            result = run_analyze(None, verbose=False, output_dir=str(output_dir))

    assert result == 0
    assert "not found" in buf.getvalue().lower()
    assert "try again" in buf.getvalue().lower()


def test_interactive_mode_cancel_on_eof_returns_1(tmp_path):
    """
    WHAT: eml_path=None, with the mocked prompt raising EOFError
         (simulating Ctrl+D / Ctrl+Z cancellation).
    WHY: The user must be able to cancel cleanly without a traceback.
    EXPECTED: Returns 1; "Exiting" message shown; no exception raised.
    """
    output_dir = tmp_path / "out"
    buf = io.StringIO()
    with patch("builtins.input", side_effect=EOFError):
        with redirect_stdout(buf):
            result = run_analyze(None, verbose=False, output_dir=str(output_dir))

    assert result == 1
    assert "exiting" in buf.getvalue().lower()
    assert "Traceback" not in buf.getvalue()


def test_quoted_path_as_direct_argument_is_cleaned(tmp_path):
    """
    WHAT: eml_path passed WITH surrounding quotes still attached, as if
         a user pasted a drag-and-dropped path directly as a CLI arg.
    WHY: clean_path_input must be applied on the direct-argument path,
         not just the interactive-prompt path.
    EXPECTED: Returns 0 despite the quotes.
    """
    eml = _write_sample(tmp_path)
    output_dir = tmp_path / "out"
    buf = io.StringIO()
    with redirect_stdout(buf):
        result = run_analyze(f'"{eml}"', verbose=False, output_dir=str(output_dir))
    assert result == 0


def test_existing_samples_still_work_unchanged(tmp_path):
    """
    WHAT: The pre-existing, already-tested sample file location pattern
         (a real repo sample under samples/phishing/).
    WHY: Backward compatibility — this exact usage must keep working
         exactly as before the new input-handling feature was added.
    EXPECTED: Returns 0.
    """
    output_dir = tmp_path / "out"
    buf = io.StringIO()
    with redirect_stdout(buf):
        result = run_analyze(
            "samples/phishing/credential_harvest_example.eml",
            verbose=False, output_dir=str(output_dir),
        )
    assert result == 0