#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Writes the public certificate bundle to stdout.
set -euo pipefail

scratch=$(mktemp -d "${TMPDIR:-/tmp}/tav-eku-fixtures.XXXXXXXX")
trap 'rm -f -- "$scratch"/{req.cnf,root.key,root.pem,leaf.key,leaf.csr,leaf.cnf}; rmdir -- "$scratch"' EXIT
export TMPDIR="$scratch"

printf '[req]\ndistinguished_name=dn\n[dn]\n' > "$scratch/req.cnf"
openssl req -config "$scratch/req.cnf" -new -x509 -newkey rsa:2048 -nodes \
    -keyout "$scratch/root.key" -out "$scratch/root.pem" -subj '/CN=TAV EKU Test Root' \
    -sha256 -days 36500 -set_serial 1 -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign' -addext 'extendedKeyUsage=critical,emailProtection'
openssl req -config "$scratch/req.cnf" -new -newkey rsa:2048 -nodes \
    -keyout "$scratch/leaf.key" -out "$scratch/leaf.csr" -subj '/CN=TAV EKU Test Leaf'

issue_leaf() {
    local serial=$1
    shift
    printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' "$@" \
        > "$scratch/leaf.cnf"
    openssl x509 -req -in "$scratch/leaf.csr" -CA "$scratch/root.pem" -CAkey "$scratch/root.key" \
        -sha256 -days 36500 -set_serial "$serial" -extfile "$scratch/leaf.cnf"
}

cat "$scratch/root.pem"
issue_leaf 2 'extendedKeyUsage=critical,codeSigning,2.100.3'
issue_leaf 3 'extendedKeyUsage=codeSigning'
issue_leaf 4
issue_leaf 5 'extendedKeyUsage=anyExtendedKeyUsage'
issue_leaf 6 'extendedKeyUsage=DER:30:00'
issue_leaf 7 'extendedKeyUsage=critical,DER:30:05:06:03:2A:03:04:00'
issue_leaf 8 'extendedKeyUsage=codeSigning' '1.2.3.4=critical,DER:30:05:06:03:2A:03:05'
