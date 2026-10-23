#!/bin/bash
# Certificates for P4Runtime with mutual TLS: one CA, and one EC P-256
# certificate per name, valid as server and as client (switches, controllers,
# API clients). The common name is the name.
#
#   pki.sh DIR NAME[=IP[,IP...]] ...
#   pki.sh /shared/pki s1=100.0.1.1 s2=100.0.1.2 c1=100.0.1.11 admin
#
# An existing CA in DIR is reused. Keep DIR private: it holds the CA key.
set -eu

[ $# -ge 2 ] || { echo "usage: $0 DIR NAME[=IP[,IP...]] ..." >&2; exit 2; }
dir=$1
shift
days=${P4ICS_PKI_DAYS:-30}
umask 077
mkdir -p "$dir"

if [ ! -s "$dir/ca.pem" ]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout "$dir/ca-key.pem" -out "$dir/ca.pem" -days "$days" -subj "/CN=P4ICS CA" \
        -addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign,cRLSign" \
        2>/dev/null
fi

for spec; do
    name=${spec%%=*}
    san="DNS:$name"
    if [ "$spec" != "$name" ]; then
        ips=${spec#*=}
        for ip in ${ips//,/ }; do san+=",IP:$ip"; done
    fi
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout "$dir/$name-key.pem" -out "$dir/$name.csr" -subj "/CN=$name" 2>/dev/null
    printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth,clientAuth\nkeyUsage=critical,digitalSignature\nbasicConstraints=CA:false\n' \
        "$san" > "$dir/$name.ext"
    openssl x509 -req -in "$dir/$name.csr" -CA "$dir/ca.pem" -CAkey "$dir/ca-key.pem" \
        -set_serial "0x$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')" -days "$days" \
        -extfile "$dir/$name.ext" -out "$dir/$name.pem" 2>/dev/null
    rm -f "$dir/$name.csr" "$dir/$name.ext"
done
