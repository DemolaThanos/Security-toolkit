# Contributing

Each tool is a separate installable package. A change belongs in that package unless it is repository CI, the licence, or the security policy.

## Setup

Python 3.11 or 3.12.

```bash
python -m pip install -e "./gha-audit[dev]"
cd gha-audit
python -m ruff check src tests
python -m ruff format --check src tests
python -m mypy
python -m bandit -r src -c pyproject.toml -q
python -m pytest
```

Repeat for the package you touched. CI runs that set on 3.11 and 3.12.

`uv lock` in the package directory refreshes `uv.lock` after a dependency change. Commit the lock with the pin.

## Probes

authrecon, subtake, corsprobe, and the devsecops-scan header check open network connections. Tests use fakes. Do not add a test, an example, or a CI step that contacts a host you do not own. `example.com` and documentation addresses are the names used in the tree.

## Secrets

Do not commit credentials, `.env` files, or key material. `pre-commit` runs gitleaks on the staged diff. CI scans the full history with `.gitleaks.toml`. A fixture that has to look like a token is built by concatenation in the test, not stored as one string.

## Reports

Scanner bugs can be reported as a public issue when the impact is a false positive or a missed check. A flaw that would let someone attack a user of the tool, or any real credential, goes through [SECURITY.md](SECURITY.md) and not a public issue.

## Licence

Contributions are under the MIT licence in [LICENSE](LICENSE). If you adapt a rule, a fingerprint, or a test vector from another project, name that project and its licence in the tool README and in [NOTICE](NOTICE).
