#!/bin/sh
#
# Regenerates the test CA, its certificates and the recorded OCSP requests/responses.
# The private key is for testing only and has no meaning outside of this test suite.

set -eu

cd "$(dirname "$0")"

rm -f ./*.crt ./*.key ./*.der index.txt

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout ca.key -out ca.crt -days 8000 -subj '/CN=OCSP Test CA' \
    -addext 'basicConstraints=critical,CA:true' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign,digitalSignature'

printf 'authorityInfoAccess=OCSP;URI:http://ocsp.test.invalid\n' > leaf.ext
for name in good revoked; do
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout "$name.key" -out "$name.csr" -subj "/CN=$name.test.invalid"
    openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key \
        -set_serial "0x7f$(openssl rand -hex 15)" -days 7999 -extfile leaf.ext -out "$name.crt"
    rm "$name.csr" "$name.key"
done
rm leaf.ext

serial() {
    openssl x509 -in "$1" -noout -serial | cut -d= -f2
}

# Status, expiration, revocation date[,reason], serial, file name, subject
printf 'V\t481231235959Z\t\t%s\tunknown\t/CN=good.test.invalid\n' "$(serial good.crt)" > index.txt
printf 'R\t481231235959Z\t250102030405Z,keyCompromise\t%s\tunknown\t/CN=revoked.test.invalid\n' "$(serial revoked.crt)" >> index.txt

for name in good revoked; do
    openssl ocsp -issuer ca.crt -cert "$name.crt" -no_nonce -reqout "$name.request.der"
    openssl ocsp -index index.txt -CA ca.crt -rsigner ca.crt -rkey ca.key \
        -reqin "$name.request.der" -respout "$name.response.der" -ndays 7
done
