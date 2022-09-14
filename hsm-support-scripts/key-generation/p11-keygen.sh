#!/usr/bin/env bash

#
# Copyright (c) 2021. Agency for Digital Government (DIGG)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#
# p11-keygen.sh - Generates a key and self signed certificate in a HSM using PKCS 11.
# This script requires that the following components are installed:
#  - OpenSC
#  - libp11
#  - OpenSSL
#
# Author: Martin Lindström <martin@litsec.se>
# Adapted by: Stefan Santesson <stefan@aaa-sec.com>
#

usage() {
    echo "Usage: $0 [options...]" >&2
    echo
    echo "   -p, --passwd           Password for HSM slot (will be prompted for if not given)"
    echo "   -s, --slot             Slot ID (Not slot index) as decimal or hex integer, for the HSM slot. Hex identifiers starts with '0x'."
    echo "   -a, --alias            The alias of the generated key"
    echo "   -m, --module           PKCS11 .so library file path (default can be defined by environment variable PKCS11_MODULE)"
    echo "   -i, --kid              Integer or hex key identifier (default is random generated)"
    echo "   -d, --dn               Certificate subject dn (default is CN=(--alias)"
    echo "       --key-type         Key type (default is EC:secp256r1)"
    echo "       --hash             Must be 'sha256', 'sha384' or 'sha512' (default is sha256)"
    echo "   -v  --valid-days       Certificate validity time (default is 365)"
    echo "       --provider-config  Takes name of the provider as input to create a SUNPKCS11 provider configuration file. Provider configuration"
    echo "                          is done per slot (not per key). No key generation if this option is selected"
    echo "       --list             Show a list of available slots. If slot (-s, --slot) is specified, list keys in the specified slot - No key generation"
    echo "       --delete           Delete private, public key and certificate for the specified alias in the specified slot"
    echo "   -h, --help             Prints this help"
    echo
    echo "Environment variables"
    echo "   PKCS11_MODULE         Defines a default PKCS11 HSM library file location if not set by the -m or --module parameter"
    echo "   LIBPKCS11             Modifies the location of the OpenSSL PKCS11 library file used for OpenSSL integration"
    echo "                         If not set, this location defaults to /usr/lib/x86_64-linux-gnu/engines-1.1/libpkcs11.so"
    echo
}

#SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

RANDOM=$$

PASSWD=""
SLOT=""
ALIAS=""
MODULE=""
KID=""
DN=""
KEY_TYPE=""
HASH=""
VALID_DAYS=""
LIST=false
DELETE=false
PROVIDER_NAME=""
PROVIDER_CONFIG=false

LIBPKCS11_LOCATION="/usr/lib/x86_64-linux-gnu/engines-1.1/libpkcs11.so"

while :
do
    case "$1" in
	-h | --help)
	    usage
	    exit 0
	    ;;
	-p | --passwd)
	    PASSWD="$2"
	    shift 2
	    ;;
	-s | --slot)
	    SLOT="$2"
	    shift 2
	    ;;
	-a | --alias)
	    ALIAS="$2"
	    shift 2
	    ;;
	-m | --module)
	    MODULE="$2"
	    shift 2
	    ;;
	-i | --kid)
	    KID="$2"
	    shift 2
	    ;;
	-d | --dn)
	    DN="$2"
	    shift 2
	    ;;
	--key-type)
	    KEY_TYPE="$2"
	    shift 2
	    ;;
	--hash)
	    HASH="$2"
	    shift 2
	    ;;
	-v | --valid-days)
	    VALID_DAYS="$2"
	    shift 2
	    ;;
	--provider-config)
	    PROVIDER_CONFIG=true
	    PROVIDER_NAME="$2"
	    shift 2
	    ;;
	--list)
	    LIST=true
	    shift 1
	    ;;
	--delete)
	    DELETE=true
	    shift 1
	    ;;
	--)
	    shift
	    break;
	    ;;
	-*)
	    echo "Error: Unknown option: $1" >&2
	    usage
	    exit 0
	    ;;
	*)
	    break
	    ;;
    esac
done

if [ ! "$LIBPKCS11" == "" ]; then
    LIBPKCS11_LOCATION=$LIBPKCS11
    echo "Using libpkcs11.so location set by ENV variable LIBPKCS11 to $LIBPKCS11_LOCATION"
fi

if [ "$MODULE" == "" ]; then
    if [ "$PKCS11_MODULE" == "" ]; then
      echo "Error: No PKCS11 module is provided" >&2
      usage
      exit 1
    else
      MODULE=$PKCS11_MODULE
    fi
    echo "Module not given, defaulting to $MODULE" >&1
fi
if [ "${SLOT}" == "" ]; then
    if [ "$LIST" == true ]; then
        # List option is set with no slot specified - then list slots
        pkcs11-tool --module $MODULE -T
        exit 0
    fi
    echo "Error: Missing HSM slot id" >&2
    usage
    exit 1
fi
if [[ $SLOT == 0x* ]]; then
    echo "Input slot hex value = $SLOT"
    SLOT=${SLOT:2}
    SLOT=$((16#$SLOT))
    echo "Decimal slot value = $SLOT"
fi
if [ "$LIST" == true ]; then
    # List option is set with slot specified - List keys in slot
    pkcs11-tool --module $MODULE --slot $SLOT -O
    exit 0
fi
if [ "$PROVIDER_CONFIG" == true ]; then
    echo "Creating PKCS11 provider configuration file for provider name $PROVIDER_NAME" >&1
    cat <<EOF >${PROVIDER_NAME}-p11
name = $PROVIDER_NAME
library = $MODULE
slot = $SLOT
EOF
    exit 0
fi
if [ "${PASSWD}" == "" ]; then
    echo -n "HSM SLOT pin: "
    read -rs PASSWD
    echo
fi
if [ "$ALIAS" == "" ]; then
    echo "Error: Missing HSM key alias" >&2
    usage
    exit 1
fi
if [ "$DELETE" == true ]; then
    read -p "Do you want to delete all keys and certificates related to alias $ALIAS in slot ${SLOT}? (Y/y) to delete: " -n 1 -r
    echo    # (optional) move to a new line
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      echo "Delete private key form HSM ..." >&1
      pkcs11-tool --delete-object --slot $SLOT --label $ALIAS --pin ${PASSWD} --login --type privkey --module $MODULE
      echo "Delete public key form HSM ..." >&1
      pkcs11-tool --delete-object --slot $SLOT --label $ALIAS --pin ${PASSWD} --login --type pubkey --module $MODULE
      echo "Delete certificate form HSM ..." >&1
      pkcs11-tool --delete-object --slot $SLOT --label $ALIAS --pin ${PASSWD} --login --type cert --module $MODULE
      echo "Done" >&1
      echo "Remaining keys:" >&1
      pkcs11-tool --module $MODULE --slot $SLOT -O
      exit 0
    else
      echo "Aborting delete action" >&2
      exit 1
    fi
fi
if [ "$KID" == "" ]; then
    KID=$RANDOM
    echo "Key ID not given, defaulting to random number $KID" >&1
fi
if ! [[ $KID =~ ^[0-9]+$ ]]; then
    echo "Error: Illegal Key ID ${KID}. Key ID must be numeric" >&2
    exit 1
fi
if ! [ $((${#KID} % 2)) -eq 0 ]; then
    echo "Key ID $KID has odd number of digits. pad with leading 1" >&1
    KID=1$KID
    echo "Padded key ID is $KID"
fi

if [ "$DN" == "" ]; then
    DN=/CN=$ALIAS
    echo "Certificate subject DN not given, defaulting to $DN" >&1
fi
if [ "$KEY_TYPE" == "" ]; then
    KEY_TYPE=EC:secp256r1
    echo "Key type not given, defaulting to $KEY_TYPE" >&1
fi
if [ "$HASH" == "" ]; then
    HASH=sha256
    echo "Hash algo not given, defaulting to $HASH" >&1
fi
if [ "$VALID_DAYS" == "" ]; then
    VALID_DAYS=365
    echo "Valid days not given, defaulting to $VALID_DAYS" >&1
fi

if [ -d "target" ]; then
    rm -rf "target"
fi
mkdir "target"

#
# Creating OpenSSL and Cert request config files
#

echo "Creating OpenSSL Config file p11-openssl.cfg"
cat <<EOF >target/p11-openssl.cfg
openssl_conf = openssl_def

[openssl_def]
engines = engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = $LIBPKCS11_LOCATION
MODULE_PATH = $MODULE
EOF

echo "Creating Cert Request config file cert.cfg"
cat <<EOF >target/cert.cfg
[req]
distinguished_name = req_distinguished_name
[req_distinguished_name]
EOF

#
# Creating the key
#

echo "Generating key of type $KEY_TYPE with id=$KID and alias=$ALIAS"
pkcs11-tool --module $MODULE --slot $SLOT --login -p ${PASSWD} --keypairgen --id $((KID)) --label $ALIAS --key-type $KEY_TYPE

#
# Generating certificate
#

KEY_ID=slot_$((SLOT))-id_$((KID))
echo "Generating self signed certificate using key identifier $KEY_ID"

OPENSSL_CONF=target/p11-openssl.cfg openssl req -x509 -new \
    -engine pkcs11 \
    -keyform engine \
    -key ${KEY_ID} \
    -passin "pass:${PASSWD}" \
    -${HASH} \
    -config target/cert.cfg \
    -subj "${DN}" \
    -days ${VALID_DAYS} \
    -out "${ALIAS}.crt"

echo "Uploading certificate to HSM"
pkcs11-tool --module $MODULE --slot $SLOT --login -p ${PASSWD} -w ${ALIAS}.crt -y cert --label $ALIAS --id $((KID))
rm -rf "target"

#
# We are done. Display result
#

echo "********************************************"
echo "     Keys in slot after key generation"
echo "********************************************"
pkcs11-tool --module $MODULE --slot $SLOT -O
echo "Done"
