# Changelog

## 0.2.0

- Package metadata includes the SPDX MIT licence, classifiers, keywords, and links. The wheel ships a copy of the repository `LICENSE`.
- Runtime and development dependencies stay pinned. `uv.lock` is the lockfile. pytest fails the run below 77% line coverage. bandit runs over `src`.
- A closed stdout pipe closes the stream and exits 0, so a truncated pipe does not print a second traceback.

- Advisory severity warnings strip control characters from the feed, so a newline in an OSV record cannot break the log line.
- `examples/risky.py` is an input that the `python-eval` rule is meant to flag.
