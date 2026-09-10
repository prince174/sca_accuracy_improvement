from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .dependency_track import DependencyTrackClient, DependencyTrackConfig


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sca-accuracy-dtrack",
        description="Exchange SBOM, VDR, and VEX documents with Dependency-Track.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command, help_text in (
        ("upload-bom", "Upload an enriched CycloneDX SBOM"),
        ("apply-vex", "Apply CycloneDX VEX decisions to existing findings"),
    ):
        child = subparsers.add_parser(command, help=help_text)
        child.add_argument("--project", required=True, help="Dependency-Track project UUID")
        child.add_argument("--file", required=True, type=Path)
    export = subparsers.add_parser("export-vdr", help="Export findings as CycloneDX VDR")
    export.add_argument("--project", required=True, help="Dependency-Track project UUID")
    export.add_argument("--output", required=True, type=Path)
    return parser


def run(args: argparse.Namespace) -> int:
    client = DependencyTrackClient(DependencyTrackConfig.from_environment())
    if args.command == "upload-bom":
        result = client.upload_bom(args.project, args.file)
    elif args.command == "apply-vex":
        result = client.apply_vex(args.project, args.file)
    else:
        result = client.export_vdr(args.project)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        result = {
            "output": str(args.output.resolve()),
            "vulnerabilities": len(result.get("vulnerabilities", [])),
        }
    print(json.dumps(result, ensure_ascii=False))
    return 0


def main() -> None:
    try:
        raise SystemExit(run(build_parser().parse_args()))
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
