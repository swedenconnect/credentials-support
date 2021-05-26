#!/bin/bash

MODULE=/usr/lib/softhsm/libsofthsm2.so
CRED_PATH=/opt/credentials-test/credentials
PIN=1234

# First initialize tokens and set the user PIN
#
pkcs11-tool --module $MODULE --slot 0 --init-token --so-pin 0000 --init-pin --pin $PIN --label RSA1
#pkcs11-tool --module $MODULE --slot 1 --init-token --so-pin 0000 --init-pin --pin $PIN --label RSA2

echo "We now have two slots set up. The slot with label RSA1 has slot-index=0 och the slot with label RSA2 has slot-index=1"

# Next, write private keys and certificates ...
#
pkcs11-tool --module $MODULE --token-label RSA1 \
  --login --pin $PIN \
  --write-object $CRED_PATH/rsa1.key \
  --type privkey --label rsa1 --id 0A01 \
  --usage-sign --usage-decrypt

pkcs11-tool --module $MODULE --token-label RSA1 \
  --login --pin $PIN \
  --write-object $CRED_PATH/rsa1.crt \
  --type cert --label rsa1 --id 0A01
  
pkcs11-tool --module $MODULE --token-label RSA1 \
  --login --pin $PIN \
  --write-object $CRED_PATH/rsa1b.key \
  --type privkey --label rsa1b --id 0A02 \
  --usage-sign --usage-decrypt

pkcs11-tool --module $MODULE --token-label RSA1 \
  --login --pin $PIN \
  --write-object $CRED_PATH/rsa1b.crt \
  --type cert --label rsa1b --id 0A02
  
#pkcs11-tool --module $MODULE --token-label RSA2 \
#  --login --pin $PIN \
#  --write-object $CRED_PATH/rsa2.key \
#  --type privkey --label rsa2 --id 0B01 \
#  --usage-sign --usage-decrypt

#pkcs11-tool --module $MODULE --token-label RSA2 \
# --login --pin $PIN \
#  --write-object $CRED_PATH/rsa2.crt \
#  --type cert --label rsa2 --id 0B01


