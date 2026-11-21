#!/usr/bin/env python3
"""Convenience launcher for the lightweight BLH-Hunter terminal scanner.

Equivalent to `python -m lazy_dorking.cli`, so you can just run:

    python scan.py nasa.gov
    python scan.py nasa.gov -p youtube,twitter --fast

See `python scan.py --help` for all options.
"""
import sys

from lazy_dorking.cli import main

if __name__ == "__main__":
    sys.exit(main())
