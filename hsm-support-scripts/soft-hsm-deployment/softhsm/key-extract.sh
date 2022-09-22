#!/usr/bin/env bash


usage() {
    echo "Usage: $0 [options...]" >&2
    echo
    echo "   -l, --location         File path to the key store file"
    echo "   -t, --type             Type of key store 'p12' or 'jks' (default is jks)"
    echo "   -p, --passwd           Password for the key store"
    echo "   -a, --alias            Alias for the extracted key"
    echo "   -o, --output            Alias for the extracted key"
    echo "   -h, --help             Prints this help"
    echo
}

DEFAULT_TYPE="jks"

ALIAS=""
PASSWD=""
TYPE=""
LOCATION=""
KEY_DIR=""

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
	-l | --location)
	    LOCATION="$2"
	    shift 2
	    ;;
	-o | --output)
	    KEY_DIR="$2"
	    shift 2
	    ;;
	-t | --type)
	    TYPE="$2"
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

if [ "$TYPE" != "p12" ]; then
    TYPE=$DEFAULT_TYPE
    echo "Defaulting to key store type jks">&1
fi

PARENT_DIR=$(dirname "$LOCATION")
FILE_NAME=$(basename "$LOCATION")
BASE_NAME="${FILE_NAME%.*}"

if [ "$KEY_DIR" == "" ]; then
    echo -n "Keystore password: "
	KEY_DIR="$PARENT_DIR/temp-key-exp-$BASE_NAME"
fi


echo "Creating temp dir for exported keys at " + $KEY_DIR
rm -rf $KEY_DIR
mkdir -p $KEY_DIR

P12_LOCATION=$LOCATION

if [ "$TYPE" == "jks" ]; then
	echo "This is a jks type - converting to p12"
	P12_LOCATION=$KEY_DIR/key-store.p12
	
    keytool -importkeystore -srckeystore $LOCATION \
	  -srcstorepass $PASSWD -srckeypass $PASSWD -srcalias $ALIAS \
	  -destalias $ALIAS -destkeystore $P12_LOCATION -deststoretype PKCS12 \
	  -deststorepass $PASSWD -destkeypass $PASSWD	
fi

echo "Extract private key from p12"
KEY_FILE=$KEY_DIR/key.pem
openssl pkcs12 -in $P12_LOCATION -nodes -nocerts -out $KEY_FILE -passin pass:$PASSWD

echo "Extract certificate from p12"
CERT_FILE=$KEY_DIR/cert.crt
openssl pkcs12 -in $P12_LOCATION -nokeys -out $CERT_FILE -passin pass:$PASSWD




	




