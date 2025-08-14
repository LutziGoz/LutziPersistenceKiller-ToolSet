# Contributing to LutziPersistenceKiller Toolset

First—thanks for wanting to help. This project targets precise, verifiable persistence eradication. Keep changes reproducible, minimal, and backed by evidence.

## How to Contribute (TL;DR)
1. **Open an Issue** first for any non-trivial change. Use the templates.
2. **Fork** the repo and create a branch: `feature/<short-name>` or `fix/<short-name>`.
3. Keep PRs **small**, focused, and with tests. Link the issue: `Fixes #123`.
4. Pass **lint, type checks, and tests** locally before opening the PR.
5. Fill out the PR template, include screenshots/logs where relevant.

---

## Scope & Philosophy
- Tools must be **safe-by-default** and **read-only** unless explicitly requested by the user (e.g., `--apply`).
- Prefer **detectors** over destructive actions; if remediation is necessary, **dry-run** and **backup** first.
- Every detector/remediator must state: **what** it flags, **why** it’s suspicious, and **how** to verify independently.

---

# clone
1. run step by step codes are below in CMD/CLI;
2. `git clone https://github.com/LutziGoz/LutziPersistenceKiller-ToolSet.git`
3. `cd LutziPersistenceKiller-ToolSet`

# create env (Python 3.11+ recommended)
- python -m venv .venv
- source .venv/bin/activate

# tooling
- pip install -U pip wheel
- pip install -r requirements.txt
- pip install -r requirements-dev.txt  # includes: pytest, ruff, black, mypy

# pre-commit hooks (optional, recommended)
- pre-commit install
