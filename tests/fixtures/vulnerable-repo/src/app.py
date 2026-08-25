"""Deliberately vulnerable sample used by the smoke test."""
import subprocess


def run(cmd):
    # Exercises Semgrep: shell injection via subprocess with shell=True.
    return subprocess.call(cmd, shell=True)
