# Contributing to ip6calc

Thank you for considering a contribution!

## Process
1. Fork the repository & create a topic branch.
2. Open an issue for large features first.
3. Write clear, minimal commits with descriptive messages.
4. Include tests (unit / fuzz where appropriate) and update README if needed.
5. Run `go test ./...` and ensure `golangci-lint` passes.
6. Open a pull request (PR) against `main`.

## Coding Guidelines
- Go 1.24+ compatible.
- Keep dependencies minimal.
- Prefer clarity over micro-optimisations unless benchmarked.
- Exported identifiers must have GoDoc comments & examples when reasonable.
- Use sentinel errors for user-visible parse/validation failures.

## Performance
If adding performance-sensitive code, include a benchmark or extend existing ones.

## Commit Message Hints
Format: `area: brief description` (e.g. `ipv6: optimize summarize merge loop`).

## Release Workflow
Releases are tagged (`vX.Y.Z`) and built via GoReleaser. Version, commit, build date embedded via ldflags.

## License
By contributing you agree your code is MIT licensed as per repository.
