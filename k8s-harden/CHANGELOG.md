# Changelog

## 0.2.0

- Package metadata includes the SPDX MIT licence, a Beta development-status classifier, keywords, and links. The wheel ships a copy of the repository `LICENSE`.
- Runtime and development dependencies stay pinned. `uv.lock` is the lockfile. pytest fails the run below 80% line coverage. bandit runs over `src`.
- A closed stdout pipe closes the stream and exits 0, so a truncated pipe does not print a second traceback.

- SARIF rules include `defaultConfiguration.level`, and result locations include a start line. Artifact URIs percent-encode spaces.
- A symlink passed as the file to check is skipped when it resolves outside its parent directory. The manifest cap stops at 10,000 files.
