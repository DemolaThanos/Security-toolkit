# Changelog

## 0.2.0

- Package metadata includes the SPDX MIT licence, classifiers, keywords, and links. The wheel ships a copy of the repository `LICENSE`.
- Runtime and development dependencies stay pinned. `uv.lock` is the lockfile. pytest fails the run below 80% line coverage. bandit runs over `src`.
- A closed stdout pipe closes the stream and exits 0, so a truncated pipe does not print a second traceback.

- A SARIF `parse-error` result includes a location when the message names a relative `.json` path. A reason that itself contains "is" does not become part of that path. Artifact URIs percent-encode spaces.
- The JSON file cap stops at 1,000. The refusal used to count one file past the cap.
