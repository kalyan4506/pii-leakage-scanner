"""
Generic line-by-line text/code file scanning utilities.

Core API:
- scan_path(...): iterate over lines in a single file path
- scan_paths(...): iterate over lines across multiple paths
- scan_text_stream(...): iterate over lines from a text stream (file-like object)
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Optional, TextIO, Union


@dataclass(frozen=True, slots=True)
class LineRecord:
    filename: str
    line_number: int
    line: str


PathLike = Union[str, Path]


def scan_text_stream(
    stream: TextIO,
    *,
    filename: str = "<stream>",
    start_line: int = 1,
    keep_newline: bool = False,
) -> Iterator[LineRecord]:
    """
    Yield LineRecord items from a text stream, line by line.

    Args:
        stream: A text-mode, file-like object (must yield str lines).
        filename: Label to attach to returned records.
        start_line: First line number to use (default 1).
        keep_newline: If False, strips a single trailing newline ("\\n") and/or
            Windows newline ("\\r\\n") from each line.
    """
    if start_line < 1:
        raise ValueError("start_line must be >= 1")

    line_no = start_line
    for raw in stream:
        line = raw if keep_newline else raw.rstrip("\r\n")
        yield LineRecord(filename=filename, line_number=line_no, line=line)
        line_no += 1


def scan_path(
    path: PathLike,
    *,
    encoding: str = "utf-8",
    errors: str = "replace",
    keep_newline: bool = False,
    start_line: int = 1,
) -> Iterator[LineRecord]:
    """
    Yield LineRecord items from a file path, line by line.

    Args:
        path: File system path to read.
        encoding: Text encoding used to decode bytes.
        errors: Decode error handling strategy (e.g. "strict", "replace", "ignore").
        keep_newline: If False, strips trailing newline characters per line.
        start_line: First line number to use (default 1).
    """
    p = Path(path)
    with p.open("r", encoding=encoding, errors=errors, newline="") as f:
        yield from scan_text_stream(
            f,
            filename=str(p),
            start_line=start_line,
            keep_newline=keep_newline,
        )


def scan_paths(
    paths: Iterable[PathLike],
    *,
    encoding: str = "utf-8",
    errors: str = "replace",
    keep_newline: bool = False,
    start_line: int = 1,
    skip_missing: bool = False,
) -> Iterator[LineRecord]:
    """
    Yield LineRecord items from multiple file paths, in order.

    Args:
        paths: Iterable of file system paths to read.
        encoding: Text encoding used to decode bytes.
        errors: Decode error handling strategy.
        keep_newline: If False, strips trailing newline characters per line.
        start_line: First line number to use for each file (default 1).
        skip_missing: If True, missing paths are ignored; otherwise FileNotFoundError is raised.
    """
    for path in paths:
        p = Path(path)
        if skip_missing and not p.exists():
            continue
        yield from scan_path(
            p,
            encoding=encoding,
            errors=errors,
            keep_newline=keep_newline,
            start_line=start_line,
        )


def scan_bytes(
    data: bytes,
    *,
    filename: str = "<bytes>",
    encoding: str = "utf-8",
    errors: str = "replace",
    keep_newline: bool = False,
    start_line: int = 1,
) -> Iterator[LineRecord]:
    """
    Convenience helper for "uploaded" content already in memory as bytes.
    """
    text = data.decode(encoding, errors=errors)
    # Splitlines keeps semantics clear and avoids platform newline issues.
    if start_line < 1:
        raise ValueError("start_line must be >= 1")
    for i, line in enumerate(text.splitlines(keepends=keep_newline), start=start_line):
        if keep_newline:
            yield LineRecord(filename=filename, line_number=i, line=line)
        else:
            yield LineRecord(filename=filename, line_number=i, line=line.rstrip("\r\n"))

