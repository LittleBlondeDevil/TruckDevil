# AGENTS.md

Guidance for coding agents working in `TruckDevil/`.

## Scope
- Repo root: `TruckDevil/`
- Package: `truckdevil/`
- Tests: `tests/`
- Python project using `setuptools`, `pytest`, and `flake8`
- No `.cursorrules`, `.cursor/rules/`, or `.github/copilot-instructions.md` exist in this repo

## Layout
- `truckdevil/truckdevil.py`: main REPL / CLI entrypoint
- `truckdevil/libs/`: shared helpers like `Device`, `Command`, `Setting`
- `truckdevil/j1939/j1939.py`: core J1939 model and interface logic
- `truckdevil/modules/`: REPL modules such as `read_messages`, `send_messages`, `ecu_discovery`, `j1939_fuzzer`
- `truckdevil/resources/json_files/`: bundled metadata required at runtime
- `tests/`: pytest suite, mostly using python-can virtual interfaces

## Python Versions
- CI runs on Python `3.10`, `3.11`, `3.12`, `3.13`, and `3.14`
- Prefer Python `3.10`-`3.14` locally
- Python `3.13` and `3.14` are covered by CI, but still verify behavior when changing version-sensitive packaging or dependency setup

## Environment Setup
From repo root:

```bash
uv sync
```

- `uv sync` installs runtime and default dev dependencies from `pyproject.toml`
- `requirements.txt` still exists for legacy pip workflows
- If `import can` fails, sync/install dependencies first

## Build / Package Commands
There is no separate compile step. Useful commands:

```bash
uv run python -m build
uv run truckdevil --version
uv tool install .
```

## Lint Commands
Preferred local commands:

```bash
uv run flake8 . --exclude .venv,.venv-*,venv,dist,build --extend-ignore E203 --count --select=E9,F63,F7,F82 --show-source --statistics
uv run flake8 . --exclude .venv,.venv-*,venv,dist,build --extend-ignore E203 --count --exit-zero --max-complexity=10 --max-line-length=120 --statistics
```

## Test Commands
Run from repo root after syncing deps:

```bash
uv run pytest tests/ -v
uv run pytest tests/test_settings.py -v
uv run pytest tests/test_settings.py::test_setting_mutator -v
uv run pytest tests/ -k setting -v
uv run pytest tests/test_settings.py -q
```

## Test Notes
- Tests use `pytest`
- Many tests use python-can `virtual`, so hardware is not required
- `tests/conftest.py` adjusts `sys.path` and CWD so resource files resolve
- Some module tests intentionally import with REPL-style paths like `import modules.send_messages`
- Cleanup is explicit; existing tests often shut down `can_bus` in `finally` blocks

## CLI / Module Conventions
- REPL commands are `cmd.Cmd` methods named `do_<command>`
- Tab completion methods are `complete_<command>`
- Module entrypoints are `main_mod(argv, device)`
- Module command classes usually subclass `libs.command.Command`
- `do_back()` generally returns `True` to leave a module REPL
- Built-in modules live under `truckdevil/modules/`
- User modules can be discovered from `TRUCKDEVIL_MODULE_PATH` or `~/.config/truckdevil/modules`
- Users can override module discovery paths with `truckdevil --module-path <dir>`
- Plugin packages can register entry points in the `truckdevil.modules` group

## Recommended Git Structure
Best setup for contributing upstream through your fork:

- `origin` -> your fork: `https://github.com/hexsecs/TruckDevil.git`
- `upstream` -> canonical repo: `https://github.com/LittleBlondeDevil/TruckDevil.git`
- In this clone, `origin` currently points to upstream

```bash
git remote rename origin upstream
git remote add origin https://github.com/hexsecs/TruckDevil.git
git fetch --all --prune
git checkout main
git fetch upstream
git rebase upstream/main
git checkout -b <topic-branch>
git push -u origin <topic-branch>
```

Open PRs from your fork branch into `upstream/main`.

## Code Style

### Imports
- Standard library first, then third-party, then local imports
- Separate groups with a blank line when groups differ
- No `isort` config exists; preserve local file style
- Runtime code often uses REPL-relative imports like `from libs.device import Device`
- Tests should usually use `from truckdevil...` unless REPL-style importing is intentional
- Avoid unused imports; there are tests checking import hygiene in some files

### Formatting
- Respect the effective line-length limit of `120`
- Use 4-space indentation
- Match surrounding style; the repo is not Black-formatted
- Keep docstrings short and practical
- Do not reformat unrelated code

### Types
- Type hints are used selectively
- Add hints when they clarify a public or library-facing interface
- Do not force a repo-wide typing rewrite
- Preserve runtime behavior in older modules that use direct `type(...)` checks

### Naming
- `snake_case` for functions, methods, variables, and tests
- `CamelCase` for classes
- `UPPER_CASE` for constants
- Keep CLI method names aligned with command names, for example `do_send` or `do_set`
- Keep module filenames lowercase with underscores

### Error Handling
- Prefer specific exceptions over bare `except:` in new code
- In CLI code, printing a helpful error and returning is common
- In library code, raise `ValueError` for invalid caller input where appropriate
- Preserve REPL usability; invalid input should usually avoid full tracebacks
- Use `finally` blocks for `can_bus`, serial, timer, and file cleanup

### State / Resource Handling
- Do not break JSON resource path resolution in `truckdevil/resources/json_files/`
- Virtual CAN tests should use unique channels to avoid cross-test leakage
- Be careful with CWD-sensitive behavior; tests deliberately adjust it
- If you open a bus, serial handle, file, or timer, make lifecycle cleanup explicit

## Change Strategy
- Make the smallest correct change
- Preserve existing REPL and module UX unless intentionally improving it
- Add or update tests when behavior changes
- Run the narrowest relevant test first, then broader tests as needed
- If you change imports or package loading, run CLI-oriented tests too
- Work from `TruckDevil/`, not the parent workspace folder
- If you need to change git remotes in this clone, confirm with the user first
