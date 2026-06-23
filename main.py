"""Backward-compat entry point.

scan4secrets v2 ships a proper package + console entry. After `pip install .`
you can simply run `scan4secrets ...`. This shim lets `python main.py ...`
keep working for users who clone-and-run.
"""

import sys
from scan4secrets.cli import main

if __name__ == "__main__":
    sys.exit(main())
