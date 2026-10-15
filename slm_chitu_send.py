"""slm_chitu_send.py - entry point. The code lives in the chitu_send package
(see chitu_send/__init__.py for the architecture notes and package layout)."""
import sys

from chitu_send.app import main

if __name__ == "__main__":
    sys.exit(main())
