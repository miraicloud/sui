#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 4 ]] || {
    echo "usage: $0 OUTPUT_DIR SIGNER_DNS VALIDATOR_A_DNS VALIDATOR_B_DNS" >&2
    exit 2
}
output=$1
signer_dns=$2
validator_a_dns=$3
validator_b_dns=$4

command -v openssl >/dev/null
command -v b2sum >/dev/null
[[ ! -e $output ]] || {
    echo "refusing to overwrite $output" >&2
    exit 1
}
umask 077
mkdir -p "$output"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/tomodachi-pki.XXXXXXXX")
trap 'rm -rf -- "$temporary"' EXIT

openssl genpkey -algorithm ED25519 -out "$output/ca.key"
openssl req -x509 -new -key "$output/ca.key" -days 3650 \
    -subj "/CN=Tomodachi Validator Failover CA" -out "$output/ca.crt"

issue() {
    local name=$1
    local usage=$2
    local dns=${3:-}
    local extension="$temporary/$name.ext"
    {
        echo "basicConstraints=critical,CA:FALSE"
        echo "keyUsage=critical,digitalSignature"
        echo "extendedKeyUsage=$usage"
        if [[ -n $dns ]]; then
            echo "subjectAltName=DNS:$dns"
        fi
    } > "$extension"
    openssl genpkey -algorithm ED25519 -out "$output/$name.key"
    openssl req -new -key "$output/$name.key" -subj "/CN=$name" \
        -out "$temporary/$name.csr"
    openssl x509 -req -in "$temporary/$name.csr" \
        -CA "$output/ca.crt" -CAkey "$output/ca.key" -CAcreateserial \
        -days 397 -extfile "$extension" -out "$output/$name.crt"
    openssl verify -CAfile "$output/ca.crt" "$output/$name.crt" >/dev/null
}

issue signer-server serverAuth "$signer_dns"
issue validator-a-agent-server serverAuth "$validator_a_dns"
issue validator-b-agent-server serverAuth "$validator_b_dns"
issue validator-a-signer-client clientAuth
issue validator-b-signer-client clientAuth
issue signer-status-reader clientAuth
issue agent-controller clientAuth

chmod 0600 "$output"/*.key
chmod 0644 "$output"/*.crt
rm -f "$output/ca.srl"
{
    echo "# BLAKE2b-256 digests of certificate DER bytes"
    for name in \
        validator-a-signer-client \
        validator-b-signer-client \
        signer-status-reader \
        agent-controller; do
        digest=$(openssl x509 -in "$output/$name.crt" -outform DER | b2sum -l 256 | awk '{print $1}')
        echo "$name: $digest"
    done
} > "$output/certificate-digests.yaml"
chmod 0600 "$output/certificate-digests.yaml"

echo "created failover PKI in $output"
echo "keep ca.key offline after issuing deployment certificates"
