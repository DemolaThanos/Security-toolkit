# Changelog

## 0.2.0

- Package metadata includes the SPDX MIT licence, classifiers, keywords, and links. The wheel ships a copy of the repository `LICENSE`.
- Runtime and development dependencies stay pinned. `uv.lock` is the lockfile. pytest fails the run below 74% line coverage. The TLS probe module is the gap. bandit runs over `src`.
- A closed stdout pipe closes the stream and exits 0, so a truncated pipe does not print a second traceback.

- `examples/README.md` states that this tree has no sample target. The command still refuses to run without `--i-am-authorized`.
