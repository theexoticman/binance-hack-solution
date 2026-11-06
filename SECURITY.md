# Security Policy

This repository is an **unaudited proof of concept**. Do not use it to hold real funds.

## Reporting a vulnerability

If you find a way for a session key, or code installed at its address, to do more than its
policies allow, please report it privately so it can be fixed and documented before it is public.

- Use GitHub's private reporting: **Security → Report a vulnerability** on this repository.
- Do not open a public issue or pull request for it.

Please include the steps to reproduce, ideally as a failing Foundry test written on top of
`test/utils/SessionTestBase.sol`, and the impact you expect.

You should get a first reply within a few days. Once a fix or a documented mitigation is
ready, the finding will be added to [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md) with
credit to you, unless you would rather stay anonymous.

## Scope

In scope: the contracts in `src/`, the session configuration in `script/lib/SessionSetup.sol`,
and any claim in `docs/` that turns out to be wrong.

Out of scope: bugs in the upstream dependencies (Safe, Safe7579, SmartSessions, EntryPoint,
OwnableValidator). Report those to their maintainers. If such a bug changes a guarantee made
here, please open an issue so the docs can be updated.

Known limitations are listed in [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md) and
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). They are not new findings.
