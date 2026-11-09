# Changelog

## 0.2.0

- Package metadata includes the SPDX MIT licence, classifiers, keywords, and links. The wheel ships a copy of the repository `LICENSE`.
- Runtime and development dependencies stay pinned. `uv.lock` is the lockfile. pytest fails the run below 80% line coverage. bandit runs over `src`.
- A closed stdout pipe closes the stream and exits 0, so a truncated pipe does not print a second traceback.

- A parse error whose path contains a space still gets a SARIF location. Artifact URIs percent-encode that space.
