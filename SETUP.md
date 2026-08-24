# Cyber-EW Fusion Cell — Clean Environment Setup Guide

**Audience:** you, resuming this project after a break.
**Goal:** get from the current messy OneDrive folder to a clean, version-controlled local project with a fully working Python environment on **both** Windows (native) and **WSL2 (Ubuntu)**, with **every** dependency installed (full parity), then verify it all runs.

Read Part 0 once. Then follow Part 1 → Part 6 in order. Part 7 (troubleshooting) and Part 8 (daily workflow) are references you'll come back to.

---

## Part 0 — Read this first: why we're doing it this way

**Two separate environments are involved, and it matters:**

1. **Your Windows machine** — where the project actually runs, where the internet package index (PyPI) works, and where the Windows-specific code lives (`windows_service.py`, `pywin32`). *This is where everything below happens.*
2. **The AI assistant's sandbox** — a locked-down Linux VM with **no PyPI access**. That's why, during the audit, `pip install` failed there for scikit-learn/FastAPI/YARA/etc. Those failures were **never a problem with your project or your machine** — just the sandbox. Nothing you install changes the sandbox, and moving folders doesn't affect it. So this guide targets **your machine only**.

**Why we're leaving OneDrive.** The single biggest source of confusion in the audit was that OneDrive had made a **partial, half-synced duplicate** of the project on `D:\` that looked catastrophically broken (missing files and functions) even though the real copy was fine. Your current folder also contains the tell-tale signs of OneDrive fighting a code project:

- **~25 "`- Copy`" files** (e.g. `main - Copy.py`, `README - Copy.md`, `requirements - Copy.txt`) — these are OneDrive *conflict copies*.
- **Three virtual-environment folders** (`venv`, `venv_legacy_broken_20260823`, `venv_old_broken`) — heavy, machine-specific, and never meant to sync.
- **No git repository at all** — which is *why* you ended up hand-copying files as backups.

A code project should live on a **local disk** and be versioned with **git**, not synced by OneDrive. That's the root-cause fix, and it's baked into the steps below.

**Decisions already made (from our discussion):**

| Decision | Choice |
|---|---|
| Where the project will live | `C:\dev\cyber-ew-fusion-cell` (local, **not** OneDrive) |
| Runtimes to set up | **Both** Windows native **and** WSL2 (Ubuntu) |
| Dependency scope | **Everything** — full parity, including native deps |
| Python version | **3.12** (see Part 0.1) |

### Part 0.1 — Which Python version, and why

Your `requirements.txt` pins **`scikit-learn==1.8.0`** (because the bundled ML model files were trained with it — mismatching risks subtle wrong results). Everything else is `>=` (flexible).

scikit-learn ships pre-built "wheels" only for specific Python versions. Its policy is to support roughly the four most recent Python minor releases at build time. **Python 3.12** is the sweet spot: mature enough that *every* dependency here (scapy, pyshark, yara-python, streamlit, pywebview, pyinstaller, pywin32) ships a 3.12 wheel, and new enough to be supported by scikit-learn 1.8.0.

- **Use Python 3.12.** (3.11 is a fine fallback.)
- **Avoid the newest release (3.13+)** for now — some native-wheel packages lag a few months behind each new Python, and a missing wheel forces a painful source build.
- **Verify for yourself in 5 seconds:** open <https://pypi.org/project/scikit-learn/1.8.0/#files> and look for a file named like `scikit_learn-1.8.0-cp312-...-win_amd64.whl`. If it's there (it will be), Python 3.12 is good to go.

### Part 0.2 — What you'll install (overview)

| Tool | Purpose | Installed how |
|---|---|---|
| **Python 3.12** | The runtime | Manual (installer) — Part 1 |
| **Git** | Version control (ends the copy-mess) | Manual (installer) — Part 1 |
| **All `pip` packages** | numpy, pandas, fastapi, scikit-learn, scapy, pyshark, yara-python, etc. | Automated by `setup_windows.ps1` / `setup_wsl.sh` |
| **Npcap** | Packet capture driver so `scapy` can sniff live traffic | Manual (installer) — Part 3.3 |
| **Wireshark / tshark** | Backend `pyshark` needs to parse packet captures | Manual (installer) — Part 3.3 |
| **Visual C++ Build Tools** | Only if a package must compile from source | Manual (installer) — Part 7 (usually not needed) |
| **WSL2 + Ubuntu** | The Linux runtime | Manual (one command) — Part 4 |

---

## Part 1 — Install the two prerequisites (Python 3.12 & Git)

Do these two manual installs first; the automated script depends on both.

### 1.1 Install Python 3.12 (Windows)

1. Go to <https://www.python.org/downloads/windows/>.
2. Under "Stable Releases", find the latest **3.12.x**, and download **"Windows installer (64-bit)"**.
3. Run the installer. **On the first screen, tick "Add python.exe to PATH"** (bottom checkbox). This is important.
4. Click **"Install Now"**. When it offers to **"Disable path length limit"** at the end, click it (helps with deep paths).
5. Confirm it worked — open a **new** PowerShell window and run:

   ```powershell
   py -3.12 --version
   ```

   You should see `Python 3.12.x`. The `py` launcher lets you keep multiple Pythons side by side and pick 3.12 explicitly.

### 1.2 Install Git (Windows)

1. Go to <https://git-scm.com/download/win> — the download starts automatically.
2. Run the installer. The **defaults are fine**; just keep clicking Next. (The default line-ending and editor choices are safe.)
3. Confirm — in a **new** PowerShell window:

   ```powershell
   git --version
   ```

   You should see `git version 2.x`.

> If either command says "not recognized", close and reopen PowerShell (PATH updates only apply to new windows). If it still fails, re-run the installer and make sure the PATH option was selected.

---

## Part 2 — Relocate the project cleanly + initialize git (automated)

You don't have to move files by hand — `setup_windows.ps1` does the relocation, the cleanup, git init, the venv, and the dependency install in one pass. Here's exactly what it does and how to run it.

**What the script copies vs. leaves behind:**

- ✅ **Copies** all real source: `core/`, `config/`, `interfaces/`, `storage/`, `utils/`, `tests/`, `data/` (including trained ML models), `docs/`, `scripts/`, `packaging/`, `deployment/`, plus `main.py`, `requirements.txt`, `setup.py`, `README.md`, `.env.example`, and the rest of your working files.
- 🚫 **Leaves behind** (regenerable or harmful to copy): all three `venv*` folders, `build/`, `dist/`, `__pycache__/`, `.pytest_cache/`, `temp/`, `logs/`, and every "`- Copy`" OneDrive conflict artifact.
- 🔒 It does **not** delete or modify your original OneDrive folder — it only *reads* from it. If anything looks wrong afterward, your original is untouched.

**How to run it:**

1. Open **PowerShell** (no admin needed for this step).
2. Allow the script to run in this session only (safe; resets when you close the window):

   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```

3. Change into your current OneDrive project folder:

   ```powershell
   cd "$env:USERPROFILE\OneDrive\Documents\cyber-ew-fusion-cell"
   ```

4. Run the setup script:

   ```powershell
   .\setup_windows.ps1
   ```

That's it — the script prints each step as it goes. When it finishes, your clean project is at `C:\dev\cyber-ew-fusion-cell`, under git, with a working venv and all dependencies. Parts 3–6 below explain what it did and cover the manual native-driver installs it can't do for you.

> **Prefer to do it by hand instead of the script?** The manual equivalent is in Part 6.

---

## Part 3 — Windows native environment (what the script sets up, plus the manual native pieces)

### 3.1 The virtual environment

The script creates a fresh, isolated environment so nothing conflicts with other Python projects:

```powershell
cd C:\dev\cyber-ew-fusion-cell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
```

When active, your prompt shows `(.venv)`. **Always activate before running the project.** To leave it later: `deactivate`.

### 3.2 The pip dependencies

With the venv active, the script runs:

```powershell
pip install -r requirements.txt
```

This installs everything in one go: `numpy`, `pandas`, `pydantic`, `fastapi`, `uvicorn`, `scikit-learn==1.8.0`, `joblib`, `scapy`, `pyshark`, `yara-python`, `stix2`, `taxii2-client`, `streamlit`, `pywebview`, `pyinstaller`, `pywin32`, `colorlog`, `requests`, `pyyaml`, `python-dateutil`, `pytest`. On Python 3.12 these all install from pre-built wheels — no compiler required.

> **`pywin32` note:** after it installs, Windows sometimes needs a one-time post-install step. The script runs it for you:
> ```powershell
> python .venv\Scripts\pywin32_postinstall.py -install
> ```

### 3.3 Native drivers `pip` can't provide (manual — do these once)

Two capabilities need OS-level software that isn't a Python package. The Python packages install fine without them, but the *live-capture* features won't work until these are present:

**Npcap — required for `scapy` live packet sniffing**

1. Download from <https://npcap.com/#download>.
2. Run the installer. On its options screen, tick **"Install Npcap in WinPcap API-compatible Mode"** (best compatibility).
3. No reboot normally needed.

**Wireshark (provides `tshark`) — required for `pyshark`**

1. Download from <https://www.wireshark.org/download.html>.
2. Run the installer with defaults. When it offers to install **Npcap**, you can let it (it's the same driver above — installing once is enough).
3. Confirm `tshark` is on PATH in a new PowerShell:
   ```powershell
   tshark --version
   ```
   If "not recognized", add `C:\Program Files\Wireshark` to your PATH, or reinstall and keep the "Add to PATH" option.

> You do **not** need these two to run `main.py --test`, the test suite, the scoring engine, the API, or the dashboard. They only matter for live network capture. If you're not doing live sniffing yet, you can install them later.

## Part 4 — WSL2 (Ubuntu) environment

WSL2 gives you a real Linux environment on the same machine — useful for Linux-side testing and closer to a production server. Note two honest limitations: the **Windows service** integration and **`pywin32`** paths are Windows-only (they're automatically skipped on Linux), and the **`pywebview` desktop GUI** needs a display, so run the dashboard from Windows, not headless WSL.

### 4.1 Install WSL2 + Ubuntu (one time)

1. Open **PowerShell as Administrator** and run:

   ```powershell
   wsl --install -d Ubuntu-24.04
   ```

   This enables WSL2 and installs Ubuntu 24.04 (which ships Python 3.12). Reboot if prompted.
2. On first launch, Ubuntu asks you to create a **username and password** — this is your Linux account, separate from Windows.
3. Verify you're on version 2:

   ```powershell
   wsl --list --verbose
   ```

   The `VERSION` column should say `2`.

> Official reference: <https://learn.microsoft.com/windows/wsl/install>.

### 4.2 Get the project into WSL and run the setup script

Keep a **separate Linux copy** of the code inside WSL's own filesystem (not `/mnt/c/...`) — Linux disk I/O is far faster there and avoids cross-filesystem permission quirks.

Inside the Ubuntu terminal:

```bash
# Copy the clean Windows project into your Linux home (one time)
cp -r /mnt/c/dev/cyber-ew-fusion-cell ~/cyber-ew-fusion-cell
cd ~/cyber-ew-fusion-cell

# Run the Linux setup script
bash setup_wsl.sh
```

`setup_wsl.sh` installs the OS-level build/runtime packages (Python 3.12 venv tooling, the libraries `yara-python` needs to build, and `tshark` for `pyshark`), creates a fresh `.venv`, and installs all pip dependencies. `pywin32` is skipped automatically on Linux because `requirements.txt` guards it with `; sys_platform == 'win32'`.

> **Keeping the two copies in sync:** use git (Part 8). Commit on one side, pull on the other — never hand-copy between them again.

---

## Part 5 — Verify everything works (do this on each environment)

Run these from the project root with the venv active. Each has an expected result so you know it truly passed, not just "didn't error".

**5.1 Core pipeline smoke test**

```bash
python main.py --test
```

Expected: a banner, engine-init logs, then a `[+] Test Results:` block, and the process exits cleanly (exit code 0).

**5.2 Automated test suite**

```bash
python -m pytest -q
```

Expected: the smoke tests pass. (During the audit, 13/14 passed in a stripped environment; with the full install here you should see the API test pass too, so aim for **all green**.)

**5.3 ML stack actually loaded (not just fallback)**

```bash
python -c "import sklearn, joblib; print('sklearn', sklearn.__version__)"
```

Expected: `sklearn 1.8.0`. If you instead see the runtime log "ML dependencies unavailable", the venv isn't active or the install didn't complete.

**5.4 API server boots**

```bash
python -c "import fastapi, uvicorn; print('api deps OK')"
# then, to actually serve it:
uvicorn interfaces.api:app --host 127.0.0.1 --port 8000
```

Expected: `Uvicorn running on http://127.0.0.1:8000`. Open <http://127.0.0.1:8000/docs> in a browser to see the interactive API docs, then stop the server with `Ctrl+C`.

**5.5 Dashboard (Windows side)**

```powershell
streamlit run run_dashboard.py
```

Expected: Streamlit prints a `localhost:8501` URL and opens your browser. (Run this from Windows, not headless WSL.) Stop with `Ctrl+C`.

**5.6 YARA / packet tooling present**

```bash
python -c "import yara; print('yara OK')"
python -c "import scapy, pyshark; print('capture libs OK')"
```

Expected: both print OK. (Live capture additionally needs Npcap + tshark from Part 3.3.)

If all of 5.1–5.6 pass, your environment is fully set up on that runtime.

---

## Part 6 — Manual equivalent (if you'd rather not use the scripts)

Everything the Windows script automates, by hand:

```powershell
# 1. Create the clean destination and copy real source only (robocopy excludes cruft)
robocopy "$env:USERPROFILE\OneDrive\Documents\cyber-ew-fusion-cell" "C:\dev\cyber-ew-fusion-cell" /E `
  /XD venv venv_old_broken venv_legacy_broken_20260823 __pycache__ .pytest_cache build dist temp logs .git `
  /XF "*- Copy*" "* - Copy*"

cd C:\dev\cyber-ew-fusion-cell

# 2. Version control
git init
git add -A
git commit -m "Initial clean import of Cyber-EW Fusion Cell"

# 3. Fresh venv + dependencies
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python .venv\Scripts\pywin32_postinstall.py -install

# 4. Verify
python main.py --test
python -m pytest -q
```

(The `.gitignore` the script writes is reproduced at the end of this file — create it before the first `git add` so the junk never enters history.)

---

## Part 7 — Troubleshooting (common install failures)

**`py -3.12` says "not recognized"** — Python 3.12 isn't installed or wasn't added to PATH. Re-do Part 1.1, ticking "Add python.exe to PATH", and open a **new** terminal.

**`pip install` fails building `scikit-learn` from source** — this means pip couldn't find a matching wheel, almost always because you're on a too-new Python. Confirm `python --version` is 3.12.x. If you're on 3.13+, recreate the venv with `py -3.12`.

**`yara-python` fails to build (Windows)** — the wheel should install directly on 3.12. If it tries to compile and fails, install **Visual C++ Build Tools** from <https://visualstudio.microsoft.com/visual-cpp-build-tools/> (tick "Desktop development with C++"), then retry `pip install yara-python`.

**`yara-python` fails to build (WSL/Linux)** — you're missing build libraries. Run `sudo apt install -y build-essential automake libtool make gcc pkg-config libssl-dev` and retry. (`setup_wsl.sh` already does this.)

**`pyshark` runs but raises "TShark not found"** — the Python package is installed but the Wireshark/tshark backend isn't on PATH. Install Wireshark (Part 3.3) or, on WSL, `sudo apt install -y tshark`.

**`scapy` can't sniff / "no libpcap provider"** — install Npcap (Part 3.3) on Windows. Live sniffing also needs an elevated/admin prompt.

**Activation blocked: "running scripts is disabled on this system"** — run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in that PowerShell window (session-only, safe), then activate again.

**`pywin32` imports fail (e.g. `import win32api` errors)** — run the post-install once: `python .venv\Scripts\pywin32_postinstall.py -install`.

**Everything "works" but logs say dependencies unavailable** — you forgot to activate the venv. Run `.\.venv\Scripts\Activate.ps1` (Windows) or `source .venv/bin/activate` (WSL) and confirm the prompt shows `(.venv)`.

---

## Part 8 — Daily workflow from now on (so the mess never returns)

1. **Open the project and activate the venv:**
   - Windows: `cd C:\dev\cyber-ew-fusion-cell` then `.\.venv\Scripts\Activate.ps1`
   - WSL: `cd ~/cyber-ew-fusion-cell` then `source .venv/bin/activate`
2. **Use git instead of copying files.** When you change something and it works:
   ```bash
   git add -A
   git commit -m "Describe what changed"
   ```
   This replaces the old "`- Copy`" habit — you can always view history or roll back with git, and no OneDrive conflict copies will ever appear again.
3. **Optional but recommended — push to a private remote** (GitHub/GitLab) as an off-machine backup: create an empty private repo, then `git remote add origin <url>` and `git push -u origin main`.
4. **If you add a dependency**, install it in the venv, then record it: `pip freeze > requirements-lock.txt` (keep `requirements.txt` as the human-edited list, and the lock file as the exact snapshot).
5. **Keep Windows and WSL copies in sync via git**, never by copying folders across `/mnt/c`.

---

## Appendix — Recommended `.gitignore`

The setup script writes this into the new project so build junk, virtual environments, secrets, logs, and OneDrive conflict copies never enter version control. Trained ML models under `data/` are intentionally **kept** (the runtime needs them).

```gitignore
# Byte-compiled / caches
__pycache__/
*.py[cod]
*.egg-info/
.eggs/
.pytest_cache/
.mypy_cache/
.coverage
htmlcov/

# Build artifacts
build/
dist/

# Virtual environments
.venv/
venv/
venv_*/
env/
ENV/

# Runtime output
logs/
*.log
temp/
tmp/
reports/*.json

# Secrets / local config (keep the example)
.env
*.env
!.env.example

# OS / editor
.DS_Store
Thumbs.db
*.swp
.idea/
.vscode/

# OneDrive conflict artifacts — must never be committed
* - Copy.*
*- Copy*
```

---

*Once you've run Part 1 (Python + Git) and then `setup_windows.ps1`, tell me how the verification steps (Part 5) went — paste any errors and I'll walk you through them. After both environments are green, we can resume the master-prompt audit against a clean, reproducible baseline.*

