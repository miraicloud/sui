# Tomodachi failover deployment bundle

These files are templates for the two-node Testnet fire drill. They contain no
private keys, certificates, tokens, hostnames, or validator identity material.

Build all four pinned binaries from one revision and record their hashes:

```sh
GIT_REVISION="$(git rev-parse HEAD)" cargo build --release \
  --bin sui-node \
  --bin sui-validator-signer \
  --bin sui-validator-agent \
  --bin sui-validator-control

sha256sum \
  target/release/sui-node \
  target/release/sui-validator-signer \
  target/release/sui-validator-agent \
  target/release/sui-validator-control
```

Every binary supports `--version` and must report the same Sui version and Git
revision. Install immutable copies under `/opt/tomodachi/bin` and point systemd
directly at those files. Do not replace them through an automatic package or
container update during a fire drill.

Generate a dedicated CA or intermediate for this deployment and separate
client certificates for validator A, validator B, the signer status reader, and
the controller. Compute allowlist IDs from certificate DER bytes:

```sh
openssl x509 -in client.crt -outform DER | b2sum -l 256
```

Compute exact profile and transport-key digests with `b2sum -l 256`. Create
service accounts and state/config directories with mode `0700`; private keys,
the control token, and signer configuration must be mode `0600`. The signer
state journal and randomness state require durable storage and backups.

Before installing the validator profiles, confirm:

- the observer profile has independent observer protocol, worker, account, and
  network keys and runs `consensus-observer` mode;
- the validator profile has no local protocol or worker key and points to the
  external signer with the candidate host's unique client certificate;
- both validator profiles identify the same signer protocol/worker keys and
  the same on-chain validator network identity;
- each agent pins the exact observer profile, validator profile, and validator
  network-key file bytes;
- the controller uses only the signer's status-reader certificate; and
- signer and agent ports are reachable only across the operator's private
  network. The dashboard remains on loopback and is reached through SSH.

Install and start the signer first, then both agents, then the controller. Start
one `sui-node` with the validator profile and the other with the observer
profile. Do not expose a second validator process merely to test the fence; use
the staged controller drill and preserve the operation record.

The first live Testnet handoff remains gated on the two-real-node rehearsal,
artifact manifest, rollback rehearsal, and explicit operator handling of the
existing validator key migration. Never discover, copy, or relocate those
private keys as an unattended deployment step.
