"""Allow ``python -m ping_shield`` (used by the generated systemd unit)."""

import sys

from .main import main

if __name__ == "__main__":
    sys.exit(main())
