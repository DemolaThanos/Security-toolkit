# Changelog

## 0.2.0

- Package metadata includes the SPDX MIT licence, classifiers, keywords, and links. The wheel ships a copy of the repository `LICENSE`.
- Runtime and development dependencies stay pinned. `uv.lock` is the lockfile. pytest fails the run below 80% line coverage. bandit runs over `src`.
- A closed stdout pipe closes the stream and exits 0, so a truncated pipe does not print a second traceback.

- A closed output pipe exits 0. `BrokenPipeError` is handled before the `OSError` clause, which used to swallow it and exit 2.
- A flow and a component that share an id no longer emit two threats with the same id. The scope suffix is incremented when that id is already used. `rate_limited: false` is described as declared off.
