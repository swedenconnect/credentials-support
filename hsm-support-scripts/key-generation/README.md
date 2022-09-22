# HSM PKCS#11 Key generation
___

This folder provides a PKCS#11 key generation script `p11-keygen.sh`. This script can be used to generate keys inside an HSM as well as issuing a self-signed certificate for that key and loading it to the HSM device.

This script is included in the example Dockerfile named `Dockerfile-softhsm-libp11` but it can be installe individually and used independently.

## Requirements
This script requires that the following components are installed:
- OpenSC
- libp11
- libengine-pkcs11-openssl
- OpenSSL

This script and the tools above must be installed on a host that is connected to the HSM device and has a HSM client installed available through a PKCS#11 library file (such as `/usr/lib/softhsm/libsofthsm2.so` for SoftHSM 2).


## Running the script in the CA container

This script can be used inside the CA container in order to initialize keys in a HSM that are to be used in a CA instance. To do this, the CA must first be started up before the instance using the keys is configured in `application-csca.properties`

After this script is used to create necessary keys and certificates in the HSM, then the CA instance can be configured with the created keys.

## Installing supporting libraries

The following script can be used to install all necessary libraries except for openssl which is expected to already exist.

```
PKCS11TOOL_VERSION=0.21.0
apt-get update && apt-get install -y pcscd libccid libpcsclite-dev libssl-dev \
    libreadline-dev autoconf automake build-essential docbook-xsl xsltproc libtool pkg-config && \
    wget https://github.com/OpenSC/OpenSC/releases/download/${PKCS11TOOL_VERSION}/opensc-${PKCS11TOOL_VERSION}.tar.gz && \
    tar xfvz opensc-*.tar.gz && \
    cd opensc-${PKCS11TOOL_VERSION} && \
    ./bootstrap && ./configure --prefix=/usr --sysconfdir=/etc/opensc && \
    make && make install && \
    cd .. && rm -rf opensc*

LIBP11_VERSION=0.4.11
apt-get install -y libengine-pkcs11-openssl
curl -fsL https://github.com/OpenSC/libp11/releases/download/libp11-${LIBP11_VERSION}/libp11-${LIBP11_VERSION}.tar.gz \
     -o libp11-${LIBP11_VERSION}.tar.gz \
        && tar -zxf libp11-${LIBP11_VERSION}.tar.gz \
        && rm libp11-${LIBP11_VERSION}.tar.gz \
        && cd libp11-${LIBP11_VERSION} \
        && ./configure \
        && make \
        && make install \
        && rm -r /usr/src/build \
```

## Making HSM Slots

In the normal case, the HSM slots should already be pre-installed in the HSM and a slot PIN should be available that allows key generation and uploading of a self-signed certificate.

For environments, such as a test environment using SoftHSM 2, necessary slots can be created using the installed pkcs11-tool command (Available from OpenSC).

The follwoing example creates a new HSM slot named "csca" as the first slot of the HSM :

```
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
    --init-token \
    --slot 0 \
    --so-pin SoSecrret \
    --init-pin --pin Secret \
    --label csca

```

Note that the slot number '0' must match the next available uninitialized slot index. Creating a new slot after the first slot consequently must specify slot '1'.

## Using the p11-keygen script

The script is a bash script and is executed from the command line by:

> `bash ./p11-keygen.sh [options...]`

A help menu is available by the -h or --help option:

```
> bash ./p11-keygen.sh --help
Usage: ./p11-keygen.sh [options...]

   -p, --passwd           Password for HSM slot (will be prompted for if not given)
   -s, --slot             Slot ID (Not slot index) as decimal or hex integer, for the HSM slot. Hex identifiers starts with '0x'.
   -a, --alias            The alias of the generated key
   -m, --module           PKCS11 .so library file path (default can be defined by environment variable PKCS11_MODULE)
   -i, --kid              Integer or hex key identifier (default is random generated)
   -d, --dn               Certificate subject dn (default is CN=(--alias)
       --key-type         Key type (default is EC:secp256r1)
       --hash             Must be 'sha256', 'sha384' or 'sha512' (default is sha256)
   -v  --valid-days       Certificate validity time (default is 365)
       --provider-config  Takes name of the provider as input to create a SUNPKCS11 provider configuration file. Provider configuration
                          is done per slot (not per key). No key generation if this option is selected
       --list             Show a list of available slots. If slot (-s, --slot) is specified, list keys in the specified slot - No key generation
       --delete           Delete private, public key and certificate for the specified alias in the specified slot
   -h, --help             Prints this help
   
Environment variables
   PKCS11_MODULE         Defines a default PKCS11 HSM library file location if not set by the -m or --module parameter
   LIBPKCS11             Modifies the location of the OpenSSL PKCS11 library file used for OpenSSL integration
                         If not set, this location defaults to /usr/lib/x86_64-linux-gnu/engines-1.1/libpkcs11.so


```

### List available Slots

First step to generate keys is to list available slots to determine their slot ID. this is done by the --list option.

Example showing 2 available slots:

```
bash ./p11-keygen.sh --list
Module not given, defaulting to /usr/lib/softhsm/libsofthsm2.so
Available slots:
Slot 0 (0xc3801ea): SoftHSM slot ID 0xc3801ea
  token label        : dgc_dc
  token manufacturer : SoftHSM project
  token model        : SoftHSM v2
  token flags        : login required, rng, SO PIN count low, token initialized, PIN initialized, other flags=0x20
  hardware version   : 2.4
  firmware version   : 2.4
  serial num         : 2a94286c8c3801ea
  pin min/max        : 4/255
Slot 1 (0x1d15753d): SoftHSM slot ID 0x1d15753d
  token label        : csca
  token manufacturer : SoftHSM project
  token model        : SoftHSM v2
  token flags        : login required, rng, token initialized, PIN initialized, other flags=0x20
  hardware version   : 2.4
  firmware version   : 2.4
  serial num         : 525dd6df9d15753d
  pin min/max        : 4/255
Slot 2 (0x2): SoftHSM slot ID 0x2
  token state:   uninitialized
```

The slot ID:s that must be used in the key generation process is `0xc3801ea` for slot with label `dgc_dc` and `0x1d15753d` for slot with label `csca`.

### Generating keys

Parameters for key generation is set as illustrated by the --help option.

The following example illustrates a key generation using the default settings (P-256 EC key with a self signed certificate signed using SHA-256, valid for 365 days and subject name set to CN=${alias})

>`bash ./p11-keygen.sh -s 0x1d15753d -a csca-key01`<br>

The following example illustrates an extended case where:

 - The key is an RSA 3072 bit key
 - The self signed certificate is signed using SHA-512
 - The self signed certificate is valid for 10 years
 - The DN of the certificate is set to C=SE,O=Example AB,OU=Digital Green Certificates,CN=Document signer 01


```
 bash ./p11-keygen.sh \
     -s 0x1d15753d \
     -a csca-key03 \
     --key-type RSA:3072 \
     --hash sha512 \
     -v 3652 \
     --dn "/C=SE/O=Example AB/OU=Digital Green Certificates/CN=Document signer 01"

```

Executing the examples above generates the following result message:

```
Public Key Object; EC  EC_POINT 256 bits
  EC_POINT:   044104..764cc270c193a50036bef8aa
  EC_PARAMS:  06082a8648ce3d030107
  label:      csca-key01
  ID:         121376
  Usage:      encrypt, verify, wrap, derive
  Access:     local
Certificate Object; type = X.509 cert
  label:      csca-key01
  subject:    DN: CN=csca-key01
  ID:         121376
Public Key Object; RSA 3072 bits
  label:      csca-key03
  ID:         8799
  Usage:      encrypt, verify, wrap
  Access:     local
Certificate Object; type = X.509 cert
  label:      csca-key03
  subject:    DN: C=SE, O=Example AB, OU=Digital Green Certificates, CN=Document signer 01
  ID:         8799

```

## Listing all keys in a slot

All generated keys and certs installed in a slot can be listed by using the --list command and specifying a specific slot

>`bash ./p11-keygen.sh -s 0x1d15753d --list`<br>

## Deleting keys from a slot

All keys and certificates for an alias can be deleted by specifying slot, alias and the command --delete:

>`bash ./p11-keygen.sh -s 0x1d15753d -a csca-key01 --delete`<br>

Password wil be prompted if not given. Keys and certificates are deleted after user re-confirmation.

## Creating a SUN PKCS#11 provider configuration file

The script can provide a SUN PKCS#11 provider configuration file accrording to [Java 11 SUN PKCS#11 Reference Guide](https://docs.oracle.com/en/java/javase/11/security/pkcs11-reference-guide1.html#GUID-C4ABFACB-B2C9-4E71-A313-79F881488BB9).

Note that this configuratioin file is genereated per slot and not per key. Each key in a slot is accessed by its alias and the slot pin, those parameters are not included in the provider configuraiton file.

A provider configuration file for the slot in the examples above is generated by:

`bash ./p11-keygen.sh --provider-config HSM-Slot -s 0x1d15753d`

This creates a file named HSM-Slot-p11 with the following content (but with the current default PKCS#11 module lib):

```
name = HSM-Slot
library = /usr/lib/softhsm/libsofthsm2.so
slot = 487945533

```


## Using the HSM key in CSCA application

The PKCS#11 provider configuration file from the previous section can be used as is, or extended according tho the PKCS11 reference guide to make the slot available to the application. Using a configuration file in the CSCA is done by the `ca-service.pkcs11.external-config-locations` property in `application-csca.properties` as illustrated by the following example:

> ca-service.pkcs11.external-config-locations=${ca-service.config.data-directory}instances/hsmtest/keys/csca-hsm-p11

An alternative to using this configuration file is to specify the parameters directly as follows:

```
ca-service.pkcs11.lib=/usr/lib/softhsm/libsofthsm2.so
ca-service.pkcs11.name=HSM-Slot
ca-service.pkcs11.slot=487945533

```

However, the downside of using the explicit configuration instead of the configuration file, is that this does not provide the cabability to customize the provider configuration settings.

Each key offered by the HSM is the specified by application properties by refering to the keys alias, and the HSM slot PIN as shown in the following example for the ca insance `hsmtest`.


```
ca-service.instance.conf.hsmtest.ca.key-source.type=pkcs11
ca-service.instance.conf.hsmtest.ca.key-source.alias=csca-key01
ca-service.instance.conf.hsmtest.ca.key-source.pass=Secr3t
ca-service.instance.conf.hsmtest.ca.key-source.reloadable-keys=true
ca-service.instance.conf.hsmtest.ocsp.key-source.type=pkcs11
ca-service.instance.conf.hsmtest.ocsp.key-source.alias=csca-key03
ca-service.instance.conf.hsmtest.ocsp.key-source.pass=S3cr3t
ca-service.instance.conf.hsmtest.ocsp.key-source.reloadable-keys=true

```
