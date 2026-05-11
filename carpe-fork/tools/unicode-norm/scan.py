#!/usr/bin/env python3
"""Carpe Unicode normalization scanner for MCP connectors.

Scans source files for invisible Unicode characters that can carry
hidden prompt-injection payloads — primarily in MCP tool descriptions
but anywhere in a connector's source is suspect.

Detects:
  - Tag characters U+E0000-U+E007F
  - Zero-width: ZWSP U+200B, ZWNJ U+200C, ZWJ U+200D, BOM U+FEFF
  - Variation selectors U+FE00-U+FE0F, U+E0100-U+E01EF
  - BiDi control: U+202A-U+202E, U+2066-U+2069

Reference: docs/carpe/architecture/mcp-security-review-pipeline.md § Stage 3.

Exit codes:
  0  no findings
  1  findings present and --fail-on-finding was set
  2  scan error (unreadable file, etc.)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterator

SCHEMA_VERSION = 1

# (low_cp, high_cp inclusive, reason). Order matters only for prettier output.
FORBIDDEN_RANGES: tuple[tuple[int, int, str], ...] = (
    (0xE0000, 0xE007F, "tag character (often used to hide instructions invisibly)"),
    (0x200B, 0x200D, "zero-width character"),
    (0xFEFF, 0xFEFF, "byte order mark / zero-width no-break space"),
    (0xFE00, 0xFE0F, "variation selector"),
    (0xE0100, 0xE01EF, "variation selector supplement"),
    (0x202A, 0x202E, "BiDi formatting (LRE/RLE/PDF/LRO/RLO)"),
    (0x2066, 0x2069, "BiDi isolate (LRI/RLI/FSI/PDI)"),
)

DEFAULT_SCAN_EXTS: frozenset[str] = frozenset({
    ".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs",
    ".json", ".jsonc", ".toml", ".yaml", ".yml",
    ".md", ".mdx", ".rst", ".txt",
    ".rs",
})

DEFAULT_EXCLUDE_DIRS: frozenset[str] = frozenset({
    ".git", ".github", "node_modules", ".venv", "venv", "env",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "dist", "build", "target", ".next", ".nuxt",
})


def classify_codepoint(cp: int) -> str | None:
    """Return a reason string if the codepoint is forbidden, else None."""
    for lo, hi, reason in FORBIDDEN_RANGES:
        if lo <= cp <= hi:
            return reason
    return None


def scan_text(text: str) -> list[dict]:
    """Walk a string and report every forbidden codepoint with context."""
    findings: list[dict] = []
    line = 1
    col = 1
    for i, ch in enumerate(text):
        reason = classify_codepoint(ord(ch))
        if reason:
            findings.append({
                "offset": i,
                "line": line,
                "column": col,
                "codepoint": f"U+{ord(ch):04X}",
                "reason": reason,
            })
        if ch == "\n":
            line += 1
            col = 1
        else:
            col += 1
    return findings


def scan_file(path: Path) -> tuple[list[dict], str | None]:
    """Return (findings, error). Either findings is a list or error is set."""
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        return [], f"non-UTF-8 file: {exc.reason}"
    except OSError as exc:
        return [], f"unreadable: {exc}"
    return scan_text(text), None


def walk(root: Path, exclude_dirs: frozenset[str], exts: frozenset[str]) -> Iterator[Path]:
    """Yield matching files under root, skipping excluded directories."""
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in exclude_dirs for part in p.parts):
            continue
        if p.suffix.lower() not in exts:
            continue
        yield p


def build_report(
    root: Path,
    exclude_dirs: frozenset[str],
    exts: frozenset[str],
) -> dict:
    file_reports: list[dict] = []
    error_reports: list[dict] = []
    scanned = 0
    for f in walk(root, exclude_dirs, exts):
        scanned += 1
        findings, err = scan_file(f)
        rel = str(f.relative_to(root)) if f.is_relative_to(root) else str(f)
        if err is not None:
            error_reports.append({"file": rel, "error": err})
            continue
        if findings:
            file_reports.append({
                "file": rel,
                "finding_count": len(findings),
                "details": findings,
            })
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": "carpe-unicode-norm",
        "scanned_root": str(root.resolve()),
        "files_scanned": scanned,
        "files_with_findings": len(file_reports),
        "errors": error_reports,
        "findings": file_reports,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--path", default=".", type=Path,
        help="Root directory to scan (default: cwd)",
    )
    parser.add_argument(
        "--output", type=Path,
        help="Write JSON report to this path (in addition to stdout)",
    )
    parser.add_argument(
        "--fail-on-finding", action="store_true",
        help="Exit 1 if any forbidden character is found",
    )
    parser.add_argument(
        "--exclude-dir", action="append", default=[],
        help="Additional directory name to skip (repeatable)",
    )
    parser.add_argument(
        "--extension", action="append", default=[],
        help="Additional file extension to scan, e.g. .vue (repeatable)",
    )
    args = parser.parse_args()

    root = args.path.resolve()
    if not root.exists():
        print(f"path does not exist: {root}", file=sys.stderr)
        return 2
    if not root.is_dir():
        print(f"path is not a directory: {root}", file=sys.stderr)
        return 2

    exclude_dirs = DEFAULT_EXCLUDE_DIRS | set(args.exclude_dir)
    exts = DEFAULT_SCAN_EXTS | {e if e.startswith(".") else "." + e for e in args.extension}

    report = build_report(root, frozenset(exclude_dirs), frozenset(exts))
    out = json.dumps(report, indent=2, ensure_ascii=False)
    print(out)
    if args.output:
        args.output.write_text(out, encoding="utf-8")

    if report["errors"]:
        for e in report["errors"]:
            print(f"warning: {e['file']}: {e['error']}", file=sys.stderr)

    if args.fail_on_finding and report["files_with_findings"]:
        print(
            f"\n{report['files_with_findings']} file(s) contain forbidden Unicode characters.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
