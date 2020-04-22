#!/bin/bash

CERT_FILE=$1
#CERT_FILE=

VALID_TO=604800

if openssl x509 -checkend ${VALID_TO} -noout -in ${CERT_FILE}
then
  echo "Valid"
else
  echo "Execute vault-pki-issuer.py"
fi
