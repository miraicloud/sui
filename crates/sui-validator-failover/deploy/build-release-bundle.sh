#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 OUTPUT.tar.gz" >&2
    exit 2
}

[[ $# -eq 1 ]] || usage
output=$1
case $output in
    /*) ;;
    *) output="$PWD/$output" ;;
esac

[[ $(uname -s) == Linux ]] || {
    echo "release bundles must be built on Linux" >&2
    exit 1
}
[[ $(uname -m) == x86_64 ]] || {
    echo "release bundles must be built on x86_64" >&2
    exit 1
}
command -v sha256sum >/dev/null
command -v tar >/dev/null

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"
target_dir=${CARGO_TARGET_DIR:-target}
case $target_dir in
    /*) ;;
    *) target_dir="$repo_root/$target_dir" ;;
esac
[[ -z $(git status --porcelain) ]] || {
    echo "refusing to build from a dirty worktree" >&2
    exit 1
}
[[ ! -e $output ]] || {
    echo "refusing to overwrite $output" >&2
    exit 1
}

revision=$(git rev-parse HEAD)
short_revision=$(git rev-parse --short=12 HEAD)
source_date_epoch=$(git show -s --format=%ct HEAD)
version=$(awk '
    $0 == "[workspace.package]" { workspace = 1; next }
    workspace && $1 == "version" { gsub(/"/, "", $3); print $3; exit }
' Cargo.toml)
[[ -n $version ]] || {
    echo "could not determine sui-node version" >&2
    exit 1
}

temporary=$(mktemp -d "${TMPDIR:-/tmp}/tomodachi-release.XXXXXXXX")
trap 'rm -rf -- "$temporary"' EXIT
bundle_name="tomodachi-sui-failover-${version}-${short_revision}-x86_64-linux"
stage="$temporary/$bundle_name"
mkdir -p "$stage/bin" "$stage/config" "$stage/systemd"

GIT_REVISION="$revision" cargo build --locked --release \
    --bin sui-node \
    --bin sui-validator-signer \
    --bin sui-validator-agent \
    --bin sui-validator-control

binaries=(
    sui-node
    sui-validator-signer
    sui-validator-agent
    sui-validator-control
)
for binary in "${binaries[@]}"; do
    install -m 0755 "$target_dir/release/$binary" "$stage/bin/$binary"
done
install -m 0644 crates/sui-validator-failover/deploy/*.yaml.example "$stage/config/"
install -m 0644 crates/sui-validator-failover/deploy/*.service "$stage/systemd/"
install -m 0644 crates/sui-validator-failover/deploy/README.md "$stage/README.md"
install -m 0755 crates/sui-validator-failover/deploy/bootstrap-pki.sh "$stage/bootstrap-pki.sh"

{
    echo "source-revision: $revision"
    echo "source-date-epoch: $source_date_epoch"
    echo "target: x86_64-unknown-linux-gnu"
    echo "rustc: $(rustc --version)"
    echo "cargo: $(cargo --version)"
    for binary in "${binaries[@]}"; do
        echo "$binary: $("$stage/bin/$binary" --version)"
    done
} > "$stage/MANIFEST.txt"

(
    cd "$stage"
    sha256sum MANIFEST.txt README.md bootstrap-pki.sh bin/* config/* systemd/* > SHA256SUMS
    sha256sum -c SHA256SUMS
)

mkdir -p "$(dirname "$output")"
tar \
    --sort=name \
    --mtime="@$source_date_epoch" \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    -C "$temporary" \
    -czf "$output" \
    "$bundle_name"
sha256sum "$output"
