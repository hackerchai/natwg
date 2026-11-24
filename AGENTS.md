# natwg agent instructions

natwg publishes a WireGuard server that sits behind carrier-grade NAT. It keeps
a STUN-discovered public UDP mapping alive, publishes it as a DNS TXT record,
and runs a client-side updater that points the peer at that endpoint.

## Local documentation

Keep internal agent guidance, ADRs, plans and validation records in `.local-docs/`.
This directory is ignored by Git and must stay out of commits and release packages.
Write tickets, PRs, plans and ADRs in English.

Read `.local-docs/plans/` before structural changes when it is present.

## Issue tracker

Track issues and specs in `hackerchai/natwg` GitHub Issues. Use the triage labels
`ready-for-agent`, `ready-for-human` and `wontfix`.

## Behaviour reference

The Python prototype this crate replaces is the reference for on-the-wire
behaviour until the Rust daemon reaches parity:
`/Users/hackerchai/.t3/scratch/2026-11-23-nat-wireguard-285e315a/natwg`.

## Checks

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
```
