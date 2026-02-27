import pytest

from pii_detection.file_scanner import scan_file


def test_scan_file_with_dummy_pii(tmp_path):
    file_path = tmp_path / "dummy_pii.txt"
    file_contents = "\n".join(
        [
            "This is a test file.",
            "Contact email: dummy.user@example.com",
            "Contact phone: 555-123-4567",
        ]
    )
    file_path.write_text(file_contents, encoding="utf-8")

    result = scan_file(str(file_path))

    assert isinstance(result, str)
    assert "dummy.user@example.com" in result
    assert "555-123-4567" in result


def test_scan_file_with_empty_file(tmp_path):
    file_path = tmp_path / "empty.txt"
    file_path.write_text("", encoding="utf-8")

    result = scan_file(str(file_path))

    assert isinstance(result, str)
    assert result == ""


def test_scan_file_missing_file_raises_file_not_found(tmp_path):
    missing_path = tmp_path / "does_not_exist.txt"

    with pytest.raises(FileNotFoundError):
        scan_file(str(missing_path))

