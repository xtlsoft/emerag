#!/bin/sh
# Regenerates the local X.509 test PKI in this directory.
#
# All CA-signed certificates use fixed validity windows so tests can pin a
# fixed "now" (2030-06-01) instead of depending on the wall clock:
#   250101000000Z .. 350101000000Z   (2025-01-01 .. 2035-01-01)
#   expired leaf: 200101000000Z .. 210101000000Z
#
# Requires the openssl CLI (used only to *produce* test data, never by emerag).
set -eu
cd "$(dirname "$0")"
OPENSSL=openssl
umask 022

WORK=tmp
rm -rf "$WORK"
mkdir -p "$WORK/newcerts"
: > "$WORK/index.txt"
echo 1000 > "$WORK/serial"

cat > "$WORK/ca.cnf" <<'EOF'
[ ca ]
default_ca = CA_default
[ CA_default ]
dir             = ./tmp
database        = $dir/index.txt
new_certs_dir   = $dir/newcerts
serial          = $dir/serial
default_md      = sha256
policy          = policy_any
email_in_dn     = no
unique_subject  = no
copy_extensions = none
rand_serial     = no
[ policy_any ]
countryName            = optional
stateOrProvinceName    = optional
localityName           = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = optional
emailAddress           = optional
EOF

START=250101000000Z
END=350101000000Z
EXP_START=200101000000Z
EXP_END=210101000000Z

key() { # key <name> [rsa|ec]
  kind=$2
  if [ "$kind" = "ec" ]; then
    "$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
      -out "$WORK/$1.key" 2>/dev/null
  else
    "$OPENSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
      -out "$WORK/$1.key" 2>/dev/null
  fi
}

csr() { # csr <name> <subject>
  "$OPENSSL" req -new -key "$WORK/$1.key" -subj "$2" -out "$WORK/$1.csr" 2>/dev/null
}

exts() { # exts <name>  (writes $WORK/<name>.ext from stdin)
  cat > "$WORK/$1.ext"
}

sign() { # sign <out> <csr> <ca-cert> <ca-key> <extname> <start> <end> [md]
  md=${8-}
  if [ -z "$md" ]; then md=sha256; fi
  "$OPENSSL" ca -batch -config "$WORK/ca.cnf" -notext \
    -in "$WORK/$2.csr" -out "$1" \
    -cert "$3" -keyfile "$4" \
    -extfile "$WORK/$5.ext" -extensions v3 \
    -startdate "$6" -enddate "$7" -md "$md" 2>/dev/null
}

# ---------------------------------------------------------------- root CA ----
key root rsa
csr root "/C=US/O=emerag test/CN=emerag Test Root CA"
exts root <<'EOF'
[v3]
basicConstraints       = critical,CA:true,pathlen:1
keyUsage               = critical,keyCertSign,cRLSign
subjectKeyIdentifier   = hash
EOF
"$OPENSSL" ca -batch -config "$WORK/ca.cnf" -notext -selfsign \
  -keyfile "$WORK/root.key" -in "$WORK/root.csr" -out root.pem \
  -extfile "$WORK/root.ext" -extensions v3 \
  -startdate "$START" -enddate "$END" -md sha256 2>/dev/null

# -------------------------------------------------------- RSA intermediate ---
key intermediate rsa
csr intermediate "/C=US/O=emerag test/CN=emerag Test Intermediate CA"
exts intermediate <<'EOF'
[v3]
basicConstraints       = critical,CA:true,pathlen:0
keyUsage               = critical,keyCertSign,cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
EOF
sign intermediate.pem intermediate root.pem "$WORK/root.key" intermediate "$START" "$END"

# --------------------------------------------------------- EC intermediate ---
key ec_intermediate ec
csr ec_intermediate "/C=US/O=emerag test/CN=emerag Test EC Intermediate CA"
exts ec_intermediate <<'EOF'
[v3]
basicConstraints       = critical,CA:true,pathlen:0
keyUsage               = critical,keyCertSign,cRLSign
subjectKeyIdentifier   = hash
EOF
sign ec_intermediate.pem ec_intermediate root.pem "$WORK/root.key" ec_intermediate "$START" "$END"

# ------------------------------------------------------- CA:false "issuer" ---
key notca rsa
csr notca "/C=US/O=emerag test/CN=emerag Not A CA"
exts notca <<'EOF'
[v3]
basicConstraints       = critical,CA:false
keyUsage               = critical,digitalSignature
EOF
sign notca.pem notca root.pem "$WORK/root.key" notca "$START" "$END"

# --------------------------------------------- pathLen 0 CA and sub-CA pair ---
key pl0 rsa
csr pl0 "/C=US/O=emerag test/CN=emerag PathLen0 CA"
exts pl0 <<'EOF'
[v3]
basicConstraints       = critical,CA:true,pathlen:0
keyUsage               = critical,keyCertSign,cRLSign
EOF
sign pl0.pem pl0 root.pem "$WORK/root.key" pl0 "$START" "$END"

key subca rsa
csr subca "/C=US/O=emerag test/CN=emerag Sub CA"
exts subca <<'EOF'
[v3]
basicConstraints       = critical,CA:true,pathlen:0
keyUsage               = critical,keyCertSign,cRLSign
EOF
sign subca.pem subca pl0.pem "$WORK/pl0.key" subca "$START" "$END"

# ------------------------------------------------------------ trusted leaf ---
key leaf rsa
csr leaf "/C=US/O=emerag test/CN=www.emerag.test"
exts leaf <<'EOF'
[v3]
basicConstraints       = critical,CA:false
keyUsage               = critical,digitalSignature,keyEncipherment
extendedKeyUsage       = serverAuth
subjectAltName         = @san
authorityKeyIdentifier = keyid:always
[san]
DNS.1 = www.emerag.test
DNS.2 = emerag.test
DNS.3 = *.wild.emerag.test
IP.1  = 127.0.0.1
EOF
sign leaf.pem leaf intermediate.pem "$WORK/intermediate.key" leaf "$START" "$END"

# --------------------------------------------------------- ECDSA P-256 leaf ---
key leaf_ec ec
csr leaf_ec "/C=US/O=emerag test/CN=ec.emerag.test"
exts leaf_ec <<'EOF'
[v3]
basicConstraints = critical,CA:false
keyUsage         = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName   = DNS:ec.emerag.test
EOF
sign leaf_ec.pem leaf_ec ec_intermediate.pem "$WORK/ec_intermediate.key" leaf_ec "$START" "$END"

# ------------------------------------------------------------ normal leaves ---
leaf_with() { # leaf_with <name> <cn> <san-body> <extra-ext-lines> [md]
  name=$1
  cn=$2
  san=$3
  extra=${4-}
  md=${5-}
  if [ -z "$md" ]; then md=sha256; fi
  key "$name" rsa
  csr "$name" "/C=US/O=emerag test/CN=$cn"
  {
    echo '[v3]'
    echo 'basicConstraints = critical,CA:false'
    echo 'keyUsage         = critical,digitalSignature,keyEncipherment'
    echo 'extendedKeyUsage = serverAuth'
    printf 'subjectAltName   = %s\n' "$san"
    if [ -n "$extra" ]; then printf '%s\n' "$extra"; fi
  } > "$WORK/$name.ext"
  sign "$name.pem" "$name" intermediate.pem "$WORK/intermediate.key" "$name" "$START" "$END" "$md"
}

leaf_with expired expired.emerag.test DNS:expired.emerag.test
key expired rsa
csr expired "/C=US/O=emerag test/CN=expired.emerag.test"
sign expired.pem expired intermediate.pem "$WORK/intermediate.key" expired "$EXP_START" "$EXP_END"

leaf_with nosan nosan.emerag.test "DNS:placeholder.emerag.test"
exts nosan <<'EOF'
[v3]
basicConstraints       = critical,CA:false
keyUsage               = critical,digitalSignature,keyEncipherment
extendedKeyUsage       = serverAuth
authorityKeyIdentifier = keyid:always
EOF
# re-sign without any subjectAltName to exercise the CN fallback
csr nosan "/C=US/O=emerag test/CN=nosan.emerag.test"
sign nosan.pem nosan intermediate.pem "$WORK/intermediate.key" nosan "$START" "$END"

leaf_with badku badku.emerag.test DNS:badku.emerag.test
exts badku <<'EOF'
[v3]
basicConstraints = critical,CA:false
keyUsage         = critical,keyCertSign
extendedKeyUsage = serverAuth
subjectAltName   = DNS:badku.emerag.test
EOF
sign badku.pem badku intermediate.pem "$WORK/intermediate.key" badku "$START" "$END"

leaf_with clienteku clienteku.emerag.test DNS:clienteku.emerag.test
exts clienteku <<'EOF'
[v3]
basicConstraints = critical,CA:false
keyUsage         = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectAltName   = DNS:clienteku.emerag.test
EOF
sign clienteku.pem clienteku intermediate.pem "$WORK/intermediate.key" clienteku "$START" "$END"

leaf_with wildidn xn--e1afmkfd.emerag.test "DNS:*.xn--e1afmkfd.test"

leaf_with critical critical.emerag.test DNS:critical.emerag.test "1.2.3.4 = critical,DER:05:00"

leaf_with sha384 sha384.emerag.test DNS:sha384.emerag.test "" sha384

leaf_with pss pss.emerag.test DNS:pss.emerag.test
# re-sign pss with RSA-PSS padding (SHA-256, salt length 32)
csr pss "/C=US/O=emerag test/CN=pss.emerag.test"
"$OPENSSL" ca -batch -config "$WORK/ca.cnf" -notext \
  -in "$WORK/pss.csr" -out pss.pem \
  -cert intermediate.pem -keyfile "$WORK/intermediate.key" \
  -extfile "$WORK/pss.ext" -extensions v3 \
  -startdate "$START" -enddate "$END" -md sha256 \
  -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 2>/dev/null

# ---------------------------------------------------------- failing leaves ---
key notca_leaf rsa
csr notca_leaf "/C=US/O=emerag test/CN=notca.emerag.test"
exts notca_leaf <<'EOF'
[v3]
basicConstraints = critical,CA:false
keyUsage         = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName   = DNS:notca.emerag.test
EOF
sign notca_leaf.pem notca_leaf notca.pem "$WORK/notca.key" notca_leaf "$START" "$END"

key plviol rsa
csr plviol "/C=US/O=emerag test/CN=plviol.emerag.test"
exts plviol <<'EOF'
[v3]
basicConstraints = critical,CA:false
keyUsage         = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName   = DNS:plviol.emerag.test
EOF
sign plviol.pem plviol subca.pem "$WORK/subca.key" plviol "$START" "$END"

# ------------------------------------------------------------ untrusted root ---
key root2 rsa
csr root2 "/C=US/O=emerag test/CN=emerag Untrusted Root CA"
exts root2 <<'EOF'
[v3]
basicConstraints     = critical,CA:true
keyUsage             = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF
"$OPENSSL" ca -batch -config "$WORK/ca.cnf" -notext -selfsign \
  -keyfile "$WORK/root2.key" -in "$WORK/root2.csr" -out root2.pem \
  -extfile "$WORK/root2.ext" -extensions v3 \
  -startdate "$START" -enddate "$END" -md sha256 2>/dev/null

key orphan rsa
csr orphan "/C=US/O=emerag test/CN=orphan.emerag.test"
exts orphan <<'EOF'
[v3]
basicConstraints = critical,CA:false
keyUsage         = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName   = DNS:orphan.emerag.test
EOF
sign orphan.pem orphan root2.pem "$WORK/root2.key" orphan "$START" "$END"

# ------------------------------------------------------------------- cleanup ---
rm -rf "$WORK"
echo "regenerated:"
ls -1 *.pem | tr '\n' ' '
echo
