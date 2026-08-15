#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 1 ]] || {
    echo "usage: $0 BUNDLE.tar.gz" >&2
    exit 2
}
archive=$1
[[ -f $archive ]] || {
    echo "bundle is not a regular file: $archive" >&2
    exit 1
}
command -v sha256sum >/dev/null
command -v tar >/dev/null

while IFS= read -r entry; do
    case "$entry" in
        /*|../*|*/../*|*/..)
            echo "unsafe archive path: $entry" >&2
            exit 1
            ;;
    esac
done < <(tar -tzf "$archive")

temporary=$(mktemp -d "${TMPDIR:-/tmp}/tomodachi-verify.XXXXXXXX")
trap 'rm -rf -- "$temporary"' EXIT
tar -xzf "$archive" -C "$temporary"
mapfile -t roots < <(find "$temporary" -mindepth 1 -maxdepth 1 -type d)
[[ ${#roots[@]} -eq 1 ]] || {
    echo "bundle must contain exactly one top-level directory" >&2
    exit 1
}
root=${roots[0]}

(
    cd "$root"
    sha256sum -c SHA256SUMS
)
revision=$(sed -n 's/^source-revision: //p' "$root/MANIFEST.txt")
[[ $revision =~ ^[0-9a-f]{40}$ ]] || {
    echo "manifest has an invalid source revision" >&2
    exit 1
}
short_revision=${revision:0:12}
for binary in sui-node sui-validator-signer sui-validator-agent sui-validator-control; do
    version=$("$root/bin/$binary" --version)
    [[ $version == *"$short_revision"* ]] || {
        echo "$binary does not report manifest revision $short_revision" >&2
        exit 1
    }
done

echo "verified bundle revision $revision"
sha256sum "$archive"
