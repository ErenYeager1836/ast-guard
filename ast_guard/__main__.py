"""
Package execution entrypoint for python -m ast_guard.
"""

import sys
from ast_guard.cli import main

if __name__ == "__main__":
    sys.exit(main())
