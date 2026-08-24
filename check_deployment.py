#!/usr/bin/env python3
"""Compatibility wrapper for the operator deployment doctor."""
from manage import command_doctor


if __name__ == "__main__":
    raise SystemExit(command_doctor(None))
