#!/bin/sh
# Regenerates the TLS test fixtures in this directory (r-binding.md §7,
# "Proving SNI"): a throwaway CA and two server certificates, for
# alpha.example.invalid and beta.example.invalid, each carrying a DNS SAN and
# no IP SAN, valid for 100 years. The CA's private key is discarded, so these
# files can sign nothing new. The keys are test-only: they name RFC 2606
# `.invalid` hosts that never resolve, and only tests trust the CA.
#
# Run from this directory with an OpenSSL 3 command-line tool:
#   sh make-certs.sh
set -eu
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
days=36500

cat > "$work/ca.cnf" <<'EOF'
[req]
distinguished_name = dn
prompt = no
x509_extensions = v3_ca
[dn]
CN = ssrfr test CA
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF
openssl req -x509 -new -newkey rsa:2048 -nodes -sha256 -days "$days" \
  -config "$work/ca.cnf" -keyout "$work/ca.key" -out ca.crt

for h in alpha beta; do
  host="$h.example.invalid"
  printf '[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = %s\n' \
    "$host" > "$work/$h.cnf"
  printf 'subjectAltName = DNS:%s\nbasicConstraints = CA:FALSE\n' \
    "$host" > "$work/$h.ext"
  openssl req -new -newkey rsa:2048 -nodes -config "$work/$h.cnf" \
    -keyout "$h.key" -out "$work/$h.csr"
  openssl x509 -req -sha256 -days "$days" -in "$work/$h.csr" \
    -CA ca.crt -CAkey "$work/ca.key" -CAcreateserial \
    -CAserial "$work/ca.srl" -extfile "$work/$h.ext" -out "$h.crt"
  # webfakes (civetweb) reads the key and the certificate from one file.
  cat "$h.key" "$h.crt" > "$h.pem"
done
