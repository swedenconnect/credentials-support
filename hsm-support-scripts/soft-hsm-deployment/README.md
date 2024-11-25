# Soft HSM deployment scripts

---

## Usage

### Prepare a softhsm adapted base image

The base image used with softhsm must install the following tools:

- Softhsm2
- pkcs11tool

Installation of these tools requires access to the "apt" command, which is not available in common java jdk images from openjdk in the latest versions of java.
For java 21, it is advisable to use "openjdk:21-jdk-buster" as FROM image to get access to the "apt" command as well as Java.

A typical start of a docker file for a softhsm adapted base image is:

```
FROM openjdk:21-jdk-buster
RUN apt update \
    && apt install -y procps softhsm2 opensc \
    && rm -rf /var/lib/apt/lists/*
```

This installs all necessary tools and then removes the imported data used by the Advanced Packaging Tool (APT) to slim the image.

### Use the softhsm deployment scripts

The folder named "softhsm" should be copied into the location of a deployment script that deploys a the
docker container of a particular application using PKCS#12 or Java key stores.

En example of a deployment script that could be located in the parent folder of the "sofhsm" folder is 
provided in the "examples" folder.

The deployment script according to the example specifies the location of a number of java keystores 
(or PKCS#12 key stores) that contains the keys that should be loaded into a SoftHSM slot for
use with the application.

The scripts in the "softhsm" folder is used to

1. Extract the keys from located JKS and/or PKCS#12 key stores
2. Create a new docker image that includes necessary SoftHSM components and scripts, including
   1. Copy the extracted keys and their certificates
   2. Installed SoftHSM 2 and pkcs11-tool
   3. Script used to import keys inside the SoftHSM
   4. Script to create a HSM configuration file for the SoftHSM slot

The example script demonstrates how the new image is created and started with all keys ready to be used inside
a SoftHSM slot installed in the container.