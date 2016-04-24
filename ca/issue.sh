#!/bin/bash
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Minimal test certificate authority using certtool (from the gnutls-bin
# package).  Usage:
#
# Run once to create a CA certificate:
# ./issue.sh --ca
#
# Create a signed certificate for <commonname>, e.g. www.host.com
# ./issue.sh <commonname>

set -euo pipefail

days=3650

# The version of certtool bundled with most distributions is not
# recent enough.
CERTTOOL=./certtool-3.4

OPENSSL=openssl

if [ -z "$1" ]; then
  echo "usage: $0 { --ca | <name> }"
  exit 1
fi

name="$1"

if [ "$name" == "--ca" ]; then
  if [ -e cakey.pem ]; then
    echo "CA cert already exists. Delete cakey.pem to create a new one"
    exit 1
  fi
  cat > info.txt <<-EOF
    cn = CA
    ca
    cert_signing_key
    expiration_days = $days
EOF

  $CERTTOOL --generate-privkey --sec-param high > newkey.pem
  $CERTTOOL --generate-self-signed \
      --template info.txt \
      --load-privkey newkey.pem \
      --outfile cacert.pem
  mv newkey.pem cakey.pem
  rm -f info.txt
else
  cat > info.txt <<-EOF
    cn = $name
    #other_name_utf8 = "1.3.6.1.4.1.311.20.2.3 ${name}@ad.chromium.org"
    expiration_days = $days
    encryption_key
    signing_key
EOF

  $CERTTOOL --generate-privkey --sec-param high > newkey.pem
  $CERTTOOL --generate-certificate \
      --template info.txt \
      --load-privkey newkey.pem \
      --outfile newcert.pem \
      --load-ca-certificate cacert.pem \
      --load-ca-privkey cakey.pem

  $OPENSSL x509 -in newcert.pem > $name.pem
  $OPENSSL x509 -in cacert.pem >> $name.pem
  cat newkey.pem >> $name.pem
  $OPENSSL pkcs12 -export -out $name.p12 -inkey newkey.pem -in newcert.pem \
      -certfile cacert.pem
  rm -f newcert.pem newkey.pem info.txt

  echo "Wrote $name.pem and $name.p12"
fi

exit 0
