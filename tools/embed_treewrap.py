#!/usr/bin/env python3
"""Embed ref/ code snippets and vector tables into TreeWrap spec Markdown."""

import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def extract_function(source: str, name: str) -> str:
    """Extract a top-level function definition by name."""
    lines = source.split("\n")
    start = None
    prefix = f"def {name}("
    for i, line in enumerate(lines):
        if line.startswith(prefix):
            start = i
            break
    if start is None:
        raise ValueError(f"function {name!r} not found")
    # Collect the function body: stop at the next top-level definition or
    # non-blank, non-comment line at column 0.
    end = len(lines)
    for i in range(start + 1, len(lines)):
        line = lines[i]
        if not line or line[0] == " " or line[0] == "\t" or line.lstrip().startswith("#"):
            continue
        # Non-blank, non-indented, non-comment line -> new top-level entity
        end = i
        break
    # Strip trailing blank lines
    result_lines = lines[start:end]
    while result_lines and result_lines[-1].strip() == "":
        result_lines.pop()
    return "\n".join(result_lines)


def extract_region(source: str, name: str) -> str:
    """Extract content between # region: name and # endregion markers."""
    lines = source.split("\n")
    start = None
    for i, line in enumerate(lines):
        if line.strip() == f"# region: {name}":
            start = i + 1
            break
    if start is None:
        raise ValueError(f"region {name!r} not found")
    end = None
    for i in range(start, len(lines)):
        if lines[i].strip() == "# endregion":
            end = i
            break
    if end is None:
        raise ValueError(f"endregion for {name!r} not found")
    result_lines = lines[start:end]
    # Strip leading/trailing blank lines
    while result_lines and result_lines[0].strip() == "":
        result_lines.pop(0)
    while result_lines and result_lines[-1].strip() == "":
        result_lines.pop()
    return "\n".join(result_lines)


def extract_snippet(file_path: Path, name: str) -> str:
    """Try function extraction first, fall back to region extraction."""
    source = file_path.read_text()
    try:
        return extract_function(source, name)
    except ValueError:
        return extract_region(source, name)


CODE_MARKER = re.compile(
    r"(<!-- begin:code:(\S+):(\S+) -->)\n"
    r".*?"
    r"(<!-- end:code:\2:\3 -->)",
    re.DOTALL,
)


def replace_code_markers(md: str) -> str:
    def replacer(m):
        begin_tag = m.group(1)
        file_rel = m.group(2)
        name = m.group(3)
        end_tag = m.group(4)
        file_path = PROJECT_ROOT / file_rel
        snippet = extract_snippet(file_path, name)
        return f"{begin_tag}\n```python\n{snippet}\n```\n{end_tag}"
    return CODE_MARKER.sub(replacer, md)


def embed(spec_path: Path) -> None:
    md = spec_path.read_text()
    md = replace_code_markers(md)
    spec_path.write_text(md)
    print(f"Embedded: {spec_path}")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <spec.md> [spec2.md ...]", file=sys.stderr)
        return 1
    for arg in sys.argv[1:]:
        embed(Path(arg))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
