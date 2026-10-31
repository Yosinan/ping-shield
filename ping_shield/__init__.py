"""ping-shield: supply-chain backdoor, persistence and threat-intel monitor for Linux.

ping-shield watches the places attackers use to keep access to a developer
workstation (SSH trust files, crontabs, systemd user units, shell start-up
files, IDE extensions), watches public security news for high-severity
threats relevant to the local machine, and reports changes to Telegram exactly
once.
"""

__version__ = "1.2.0"

__all__ = ["__version__"]
