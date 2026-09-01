"""``python -m traphy`` — the same entry point as the ``traphy`` command."""

from __future__ import annotations

import sys

from traphy.cli import main

if __name__ == "__main__":
    sys.exit(main())
