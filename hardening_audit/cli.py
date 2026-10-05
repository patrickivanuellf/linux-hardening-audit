"""Command line interface."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .checks import Context, run_all
from .report import render_json, render_markdown, render_text, score


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hardening_audit",
        description="Read-only security configuration audit for Linux hosts.",
    )
    p.add_argument("--root", default="/",
                   help="filesystem root to audit (default: / for the live host; "
                        "use a directory to audit an extracted image offline)")
    p.add_argument("--format", choices=["text", "json", "md"], default="text",
                   help="report format (default: text)")
    p.add_argument("-o", "--output", help="write the report to a file instead of stdout")
    p.add_argument("--fail-under", type=int, metavar="SCORE",
                   help="exit with status 1 if the score is below SCORE (useful in CI)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.root)
    if not root.is_dir():
        print(f"error: root '{args.root}' is not a directory", file=sys.stderr)
        return 2

    ctx = Context(root)
    results = run_all(ctx)
    target = f"{ctx.root} ({'live host' if ctx.live else 'offline tree'})"

    if args.format == "json":
        text = render_json(results, target)
    elif args.format == "md":
        text = render_markdown(results, target)
    else:
        use_color = (args.output is None and sys.stdout.isatty()
                     and "NO_COLOR" not in os.environ)
        text = render_text(results, target, color=use_color)

    if args.output:
        Path(args.output).write_text(text)
    else:
        sys.stdout.write(text)

    if args.fail_under is not None and score(results) < args.fail_under:
        return 1
    return 0
