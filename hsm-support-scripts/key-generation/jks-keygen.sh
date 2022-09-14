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
# This script generates a key pair and issues a self signed certificate and creates a
# Java Key Store (JKS) for the generated key pair and certificate ({alias}.jks)
#
# Author: Martin Lindström <martin@litsec.se>
# Adapted by: Stefan Santesson <stefan@aaa-sec.com>
#

usage() {
    echo "Usage: $0 [options...]" >&2
    echo
    echo "   -p, --passwd           Password used to protect the resulting service JKS (will be prompted for if not given)"
    echo "   -a, --alias            Alias for the generated key (default is 'key01'"
    echo "   -d, --dn               Certificate subject dn in the form '/C=SE/O=Org[/OU=Org Unit]/CN=unique name' (Must be specified)"
    echo "   -t  --target-folder    An absolute or relative path to the folder where the resulting JKS files will be stored (default is execution folder)"
    echo "   -k, --key-type         Key type either in the form EC:{curve-name} or RSA:{key size}(default is EC:secp256r1)"
    echo "       --hash             Must be 'sha256', 'sha384' or 'sha512' (default is sha256)"
    echo "   -v  --valid-days       Certificate validity time (default is 365)"
    echo "   -o  --output-file      Name of the output file without file name extension"
    echo "   -h, --help             Prints this help"
    echo
}

#SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

DEFAULT_KEY_TYPE="EC:secp256r1"
DEFAULT_HASH="sha256"
DEFAULT_VALID_DAYS=365
DEFAULT_PROFILE="default"
DEFAULT_ALIAS="key01"

ALIAS=""
PROFILE=""
TARGET_FILE=""
PASSWD=""
DN=""
KEY_TYPE=""
HASH=""
VALID_DAYS=""
TARGET_FOLDER=""
OUTPUT_FILE=""

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
	-a | --alias)
	    ALIAS="$2"
	    shift 2
	    ;;
	-d | --dn)
	    DN="$2"
	    shift 2
	    ;;
	-k | --key-type)
	    KEY_TYPE="$2"
	    shift 2
	    ;;
	-t | --target-folder)
	    TARGET_FOLDER="$2"
	    shift 2
	    ;;
	-o | --output-file)
	    OUTPUT_FILE="$2"
	    shift 2
	    ;;
	--hash)
	    HASH="$2"
	    shift 2
	    ;;
	--profile)
	    PROFILE="$2"
	    shift 2
	    ;;
	-v | --valid-days)
	    VALID_DAYS="$2"
	    shift 2
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

if [ "${PASSWD}" == "" ]; then
    echo -n "Keystore password: "
    read -s PASSWD
    echo
fi
if [ "$DN" == "" ]; then
    echo "Error: Missing Subject DN" >&2
    usage
    exit 1
fi
if [ "$KEY_TYPE" == "" ]; then
    KEY_TYPE=$DEFAULT_KEY_TYPE
    echo "Key type not given, defaulting to $KEY_TYPE" >&1
fi
if [ "$ALIAS" == "" ]; then
    ALIAS=$DEFAULT_ALIAS
    echo "Alias not given, defaulting to $ALIAS" >&1
fi
if [ "$HASH" == "" ]; then
    HASH=$DEFAULT_HASH
    echo "Hash algo not given, defaulting to $HASH" >&1
fi
if [ "$VALID_DAYS" == "" ]; then
    VALID_DAYS=$DEFAULT_VALID_DAYS
    echo "Valid days not given, defaulting to $VALID_DAYS" >&1
fi
if [ "$TARGET_FOLDER" != "" ]; then
    if [ ! -d "$TARGET_FOLDER" ]; then
        echo "Creating target folder $TARGET_FOLDER" >&1
        mkdir "$TARGET_FOLDER"
    fi
    TARGET_FOLDER=${TARGET_FOLDER}/
fi
if [ "$OUTPUT_FILE" == "" ]; then
    OUTPUT_FILE=$ALIAS
fi

# Only support default profile for now
PROFILE=$DEFAULT_PROFILE
TARGET_FILE=${TARGET_FOLDER}${OUTPUT_FILE}
echo "Profile set to DEFAULT certificate profile" >&1

if [ -d "_temp" ]; then
    rm -rf "_temp"
fi
mkdir "_temp"

#
# Creating Cert request config files
#

echo "Creating Cert Request config files" >&1

if [ "$PROFILE" == "default" ]; then

cat <<EOF >_temp/cert.cfg
[req]
distinguished_name = req_distinguished_name
[req_distinguished_name]
EOF

else
  echo "Unsupported profile" >&1
  exit 1
fi

#
# Creating the key
#

ALGO_PARAM=""
if [ "${KEY_TYPE:0:2}" == "EC" ]; then
  ALGO_PARAM=${KEY_TYPE:3}

  echo "Generating EC key pair of type: $ALGO_PARAM" >&1
  openssl ecparam -name $ALGO_PARAM -genkey -noout -out _temp/private.key
  openssl pkcs8 -topk8 -in _temp/private.key -passout "pass:$PASSWD" -out _temp/private.pem
else
  echo "Generating RSA key pair of size: $ALGO_PARAM" >&1
  ALGO_PARAM=${KEY_TYPE:4}
  openssl genrsa -aes128 -passout "pass:$PASSWD" -out _temp/private.pem $ALGO_PARAM
fi


#
# Generating certificate
#

echo "Generating self signed certificate for profile $PROFILE" >&1
echo "Certificate valid for $VALID_DAYS days"

openssl req -x509 -new \
    -key _temp/private.pem \
    -passin "pass:$PASSWD" \
    -$HASH \
    -config _temp/cert.cfg \
    -subj "$DN" \
    -days $((VALID_DAYS)) \
    -out ${TARGET_FILE}.crt

echo "Creating P12 key store" >&1
if [ -f "${TARGET_FILE}.p12" ]; then
  echo "Target .p12 file exists - removing old .p12" >&1
    rm "${TARGET_FILE}.p12"
fi
openssl pkcs12 -export -in ${TARGET_FILE}.crt -inkey _temp/private.pem -name "$ALIAS" -passin "pass:$PASSWD" -passout "pass:$PASSWD" -out ${TARGET_FILE}.p12

echo "Converting to JKS key store" >&1
if [ -f "${TARGET_FILE}.jks" ]; then
  echo "Target JKS file exists - removing old JKS" >&1
    rm "${TARGET_FILE}.jks"
fi

keytool -importkeystore -srckeystore ${TARGET_FILE}.p12 \
    -srcstoretype PKCS12 \
    -srcstorepass "$PASSWD" \
    -destkeystore ${TARGET_FILE}.jks \
    -deststoretype JKS \
    -deststorepass "$PASSWD" \

#
# Remove temporary files
#
rm -rf _temp

#
# We are done.
#

echo "Done" >&1
