#!/usr/bin/env bash

usage() {
    echo "Usage: $0 [options...]" >&2
    echo
    echo "   -p, --pin              Pin for the HSM slot"
    echo "   -l, --label            Label for the HSM slot (default = 'softhsmslot')"
    echo "   -h, --help             Prints this help"
    echo
}

PIN=""
LABEL=""

while :
do
    case "$1" in
	-h | --help)
	    usage
	    exit 0
	    ;;
	-p | --pin)
	    PIN="$2"
	    shift 2
	    ;;
	-l | --label)
	    LABEL="$2"
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


if [ "$PIN" == "" ]; then
    PIN="1234"
    echo "Defaulting to default pin '1234'">&1
fi

if [ "$LABEL" == "" ]; then
    LABEL="softhsmslot"
    echo "Defaulting to default HSM slot label 'softhsmslot'">&1
fi


echo "Initializing key klot in soft hsm"
MODULE="/usr/lib/softhsm/libsofthsm2.so"

pkcs11-tool --module $MODULE --init-token --slot 0 --so-pin 1217813 --init-pin --pin $PIN --label $LABEL

KEY_ID=1000

for keydir in "/opt/keys"/*
do
	ALIAS=$(basename "$keydir")
	
	echo "Importing key from $keydir"
	KEY_FILE=$keydir/key.pem
	pkcs11-tool --module $MODULE -p $PIN -l -w $KEY_FILE -y privkey -a $ALIAS -d $KEY_ID --usage-sign --usage-decrypt

	echo "Importing key from $keydir"
	CERT_FILE=$keydir/cert.crt
	pkcs11-tool --module $MODULE -p $PIN -l -w $CERT_FILE -y cert -a $ALIAS -d $KEY_ID
	
	KEY_ID=$(( $KEY_ID + 1 ))
	
done


# Create HSM slot configuration file
PROVIDER_NAME="SoftHsmProvider"

slot_id_line=$(pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so -L | grep "Slot 0")
slot_id_hex="${slot_id_line##*0x}"
SLOT=$((16#$slot_id_hex))

echo "Creating PKCS11 provider configuration file for provider name $PROVIDER_NAME" >&1
cat <<EOF >/opt/${PROVIDER_NAME}-p11
name = $PROVIDER_NAME
library = $MODULE
slot = $SLOT
EOF
