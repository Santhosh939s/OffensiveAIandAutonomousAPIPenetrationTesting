"""Intentionally Vulnerable Local API Security Laboratory.

Designed exclusively for local, controlled testing and validation of
the Autonomous API Penetration Testing Controller. Runs strictly on 127.0.0.1.
"""

from .app import create_app, run_lab_server

__all__ = ["create_app", "run_lab_server"]

