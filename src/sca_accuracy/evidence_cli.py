"""Import existing analysis results: python -m sca_accuracy.evidence_cli DIRECTORY."""

import argparse
from pathlib import Path

from .evidence import configured_store


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--kind", choices=("build", "synthetic"), default="build")
    args = parser.parse_args()
    store = configured_store()
    if store is None:
        parser.error("Set SCA_EVIDENCE_DSN")
    store.migrate()
    print(store.ingest(args.directory, kind=args.kind))


if __name__ == "__main__":
    main()
