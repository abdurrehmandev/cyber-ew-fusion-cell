#!/usr/bin/env bash
# =============================================================================
# Clean setup for Cyber-EW Fusion Cell on WSL2 / Ubuntu (24.04 recommended).
#
# HOW TO RUN (inside your Ubuntu terminal), from the project root:
#     bash setup_wsl.sh
#
# It installs the OS-level build/runtime packages, creates a fresh Python 3.12
# virtual environment (.venv), installs all pip dependencies (pywin32 is skipped
# automatically on Linux), and runs verification.
#
# Note: keep the Linux copy under your home dir (e.g. ~/cyber-ew-fusion-cell),
# NOT under /mnt/c, for speed and to avoid permission quirks.
# =============================================================================
set -euo pipefail

info(){ printf '\033[36m[*] %s\033[0m\n' "$1"; }
ok(){   printf '\033[32m[+] %s\033[0m\n' "$1"; }
warn(){ printf '\033[33m[!] %s\033[0m\n' "$1"; }
fail(){ printf '\033[31m[X] %s\033[0m\n' "$1"; exit 1; }

# --- sanity ---
[ -f main.py ] && [ -f requirements.txt ] || fail "Run this from the project root (main.py / requirements.txt not found)."

echo
info "Cyber-EW Fusion Cell - WSL2/Ubuntu clean setup"
echo

# --- 1. OS packages ---
# DEBIAN_FRONTEND=noninteractive prevents the tshark 'allow non-root capture?'
# dialog from blocking the script (it safely defaults to 'No').
export DEBIAN_FRONTEND=noninteractive
info "Installing OS packages (sudo may prompt for your password)..."
sudo apt-get update -y
sudo apt-get install -y \
  python3.12 python3.12-venv python3.12-dev python3-pip \
  build-essential automake libtool make gcc pkg-config \
  libssl-dev flex bison \
  git tshark
ok "OS packages installed"

# --- 2. Pick the interpreter ---
if command -v python3.12 >/dev/null 2>&1; then
  PY=python3.12
else
  warn "python3.12 not found (are you on Ubuntu 24.04?). Falling back to python3."
  warn "If pip later fails to find a scikit-learn==1.8.0 wheel, install 3.12 via the deadsnakes PPA:"
  warn "  sudo add-apt-repository ppa:deadsnakes/ppa && sudo apt update && sudo apt install python3.12 python3.12-venv"
  PY=python3
fi
info "Using interpreter: $($PY --version 2>&1)"

# --- 3. Fresh venv + dependencies ---
info "Creating fresh virtual environment (.venv)..."
rm -rf .venv
$PY -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip >/dev/null
ok "venv created and pip upgraded"

info "Installing all dependencies from requirements.txt (pywin32 auto-skips on Linux)..."
pip install -r requirements.txt
ok "All pip dependencies installed"

# --- 4. Verification ---
echo
info "VERIFY 1/2 -> python main.py --test"
if python main.py --test; then ok "main.py --test passed (exit 0)"; else warn "main.py --test returned nonzero - review output above."; fi

echo
info "VERIFY 2/2 -> python -m pytest -q"
if python -m pytest -q; then ok "Test suite passed"; else warn "Some tests failed - review output above (see SETUP.md Part 7)."; fi

# --- Done ---
echo
ok "WSL setup complete."
info "Project location : $(pwd)"
info "Activate next time: cd \"$(pwd)\" && source .venv/bin/activate"
warn "pyshark uses tshark (installed). Live scapy sniffing in WSL needs root and has limited NIC access - prefer Windows for live capture."
echo
