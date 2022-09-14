#!/bin/bash
cd "$(dirname "$0")"

# This example shows how to use the scripts and Dockerfile in the "softhsm" folder to
# extract keys and certificates from a number of key stores and to create a new
# docker image extended with SoftHSM and with the extracted keys and certificates imported
# and ready to be used by the application running in a container using that image

# NOTE: This example script suppose that it is placed in the parent folder of the "softhsm" folder
# and that this script has the right to create a folder "keys" in the "softhsm" folder for temporary
# key storage

# NOTE: This script should be executed either using './' or 'bash' (not using 'sh').

# Key identifiers used as alias for the hsm key access
key_id=(
  "ca01-ca" \
  "ca01-ocsp" \
  "root01-ca" \
	"tls-ca" \
	"tls-ocsp")
# Key store locations used as key sources
keystore=(
  "/opt/docker/ca/instances/ca01/keys/key-ca.jks" \
  "/opt/docker/ca/instances/ca01/keys/key-ocsp.jks" \
	"/opt/docker/ca/instances/rot01/keys/rot01-ca.jks" \
	"/opt/docker/ca/instances/tls-client/keys/key-ca.jks" \
	"/opt/docker/ca/instances/tls-client/keys/key-ocsp.jks")
# Passwords for key stores
password=(
	"1234" \
	"1234" \
	"1234" \
	"1234" \
	"1234")
# Aliases for the keystore keys used to export these keys
alias=(
	"ca" \
	"ocsp" \
	"rot-ca" \
	"ca" \
	"ocsp")

# Other build parameters
hsm_pin="s3cr3t"
hsm_slot_label="cakeys"
docker_from_image="headless-ca:m1"
docker_build_image="headless-ca:latest"
key_store_type="jks"

echo "extracting keys"
for i in "${!key_id[@]}"; do
	bash softhsm/key-extract.sh -p ${password[$i]} -t $key_store_type -a ${alias[$i]} -l ${keystore[$i]} -o softhsm/keys/${key_id[$i]}
done

echo "Building docker image with imported keys"
docker build -f softhsm/Dockerfile-key-import \
	--build-arg FROM_IMAGE=$docker_from_image \
	--build-arg PIN=$hsm_pin \
	--build-arg SLOT_LABEL=$hsm_slot_label \
	--build-arg KEY_DIR='softhsm/keys' \
	--build-arg SCRIPT_DIR='softhsm' \
	-t $docker_build_image .

echo "Removing key directory"
rm -rf softhsm/keys

echo "Undeploying current running docker image ..."
docker rm hca --force

echo "Re-deploying docker image with imported soft-hsm keys ..."

docker run -d --name hca --restart=always \
  -p 8080:8080 -p 8009:8009 -p 8443:8443 -p 8000:8000 -p 8006:8006 -p 8008:8008 \
  -e "SPRING_CONFIG_ADDITIONAL_LOCATION=/opt/ca/" \
  -e "SPRING_PROFILES_ACTIVE=nodb, softhsm" \
  -e "TZ=Europe/Stockholm" \
  -v /etc/localtime:/etc/localtime:ro \
  -v /opt/docker/ca/:/opt/ca \
  $docker_build_image

# Display log (optional)
docker logs hca -f --tail 100