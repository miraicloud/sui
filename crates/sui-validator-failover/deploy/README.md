# Tomodachi failover deployment bundle

These files are templates for the two-node Testnet fire drill. They contain no
private keys, certificates, tokens, hostnames, or validator identity material.

Build all four pinned binaries from one revision on an x86_64 Linux builder and
record their hashes. The build script refuses a dirty tree or a non-Linux,
non-x86_64 host, uses `Cargo.lock`, embeds the full source revision in every
binary, and emits a reproducible archive with an internal checksum manifest:

```sh
crates/sui-validator-failover/deploy/build-release-bundle.sh \
  /tmp/tomodachi-sui-failover.tar.gz
crates/sui-validator-failover/deploy/verify-release-bundle.sh \
  /tmp/tomodachi-sui-failover.tar.gz
```

Every binary supports `--version` and must report the same Sui version and Git
revision. Install immutable copies under `/opt/tomodachi/bin` and point systemd
directly at those files. Do not replace them through an automatic package or
container update during a fire drill.

Generate a dedicated CA or intermediate for this deployment and separate
client certificates for validator A, validator B, the signer status reader, and
the controller. The bootstrap script creates only transport credentials; it
does not read, create, copy, or migrate Sui validator signing keys:

```sh
crates/sui-validator-failover/deploy/bootstrap-pki.sh \
  /secure/failover-pki \
  validator-signer.internal \
  validator-a.internal \
  validator-b.internal
```

The generated `certificate-digests.yaml` contains the exact BLAKE2b-256 DER
digests for the signer and agent allowlists. Keep `ca.key` offline after issuing
the deployment certificates. Certificate bootstrap requires Linux `b2sum`
because BLAKE2b-256 is not a truncation of BLAKE2b-512.

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

The signer and agent units run a local, non-mutating configuration check before
each start. After every service is reachable and the observer is warm, run the
controller's end-to-end read-only preflight:

```sh
/opt/tomodachi/bin/sui-validator-control \
  --config-path /etc/sui-validator-control/control.yaml \
  --preflight
```

It queries both mTLS agents, both Sui metrics endpoints, and the signer with the
status-reader certificate. It prints the same server-authoritative snapshot
used by the dashboard and exits nonzero unless the exact source, target, signer
lease generation, key identities, epoch, DKG state, voting roles, and lag bounds
are eligible. It never calls a stop, start, profile activation, lease, or
signing method.

The real local Sui swarm test already exercises the complete A-to-B-to-A
candidate lifecycle with a consensus observer, separate databases, profiles,
and signer certificates, checkpoint progress, an epoch transition,
signer-owned DKG, demotion back to observer, and strictly increasing lease
generations. The networked controller test separately exercises mutual TLS,
stop/fence/start ordering, and stale-holder rejection.

The first live Testnet handoff remains gated on reproducing that round trip on
the two real hosts, a pinned Linux artifact manifest, host/process failure
injection, and explicit operator handling of the existing validator key
migration. Never discover, copy, or relocate those private keys as an unattended
deployment step.
