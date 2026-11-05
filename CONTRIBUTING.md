# Contributing

Thanks for contributing to UJANI Enterprise AI.

## Start here
Read [README.md](README.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/SECURITY.md](docs/SECURITY.md) and [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Development

```sh
cargo fmt --all -- --check
cargo test --workspace
```

## Expectations

- Never enrol or use a device without explicit authorisation.
- Never hide compute activity from device owners or administrators.
- Keep control-plane and worker responsibilities separated.
- Treat scheduler decisions as untrusted until the worker validates them.
- Add tests for policy denials, revocation, quota and failure cases.
- Do not claim production-grade isolation without OS enforcement and review.
- Do not commit credentials, production data or private model artefacts.

Contributions are provided under the repository's existing GPL-3.0 terms.
