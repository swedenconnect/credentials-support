![Logo](https://github.com/swedenconnect/technical-framework/blob/master/img/sweden-connect.png)

# credentials-support

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.security/credentials-support/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.security/credentials-support)

Java libraries for PKI credentials support, including PKCS#11 and HSM:s.

---

## Table of contents

1. [**Overview**](#overview)

    1.1. [API Documentation](#api-documentation)
    
    1.2. [Maven](#maven)
    
2. [**Credential types**](#credential-types)

    2.1. [BasicCredential](#basiccredential)
  
    2.2. [KeyStoreCredential](#keystorecredential)
  
    2.3. [Pkcs11Credential](#pkcs11credential)
    
3. [**PkiCredential Features**](#pkicredential-features)

    3.1. [Credential Name](#credential-name)
    
    3.2. [Transformation to other Formats](#transformation-to-other-formats)
    
    3.3. [Testing and Reloading](#testing-and-reloading)
    
    3.4. [Credential Metadata](#credential-metadata)
    
4. [**Builders and Factories**](#builders-and-factories)

    4.1. [KeyStore Builder and Factories](#keystore-builder-and-factories)
    
    4.2. [Credential Factories](#credential-factories)

5. [**Credential Bundles and Configuration Support**](#credential-bundles-and-configuration-support)

    5.1. [The Bundles Concept](#the-bundles-concept)
    
    5.2. [Configuration Support](#configuration-support)
    
    5.2.1. [Basic Configuration Concepts](#basic-configuration-concepts)    
    
    5.2.2. [Key Store Configurations](#key-store-configurations)
    
    5.3. [Spring Boot Configuration Support](#spring-boot-configuration-support)
    
6. [**Monitoring**](#monitoring)

7. [**Credential Containers for Managing Keys**](#credential-containers)

    7.1. [Creating a Credential Container](#creating-a-credential-container)
    
    7.1.1. [HSM-based Credential Containers](#hsm-based-credential-container)
    
    7.1.2. [In-memory KeyStore-based Credential Container](#in-memory-keystore-based-credential-container)
    
    7.1.3. [In-memory Credential Container](#in-memory-credential-container)
    
    7.2. [Using the Credential Container](#using-the-credential-container)
    
8. [**Spring Support**](#spring-support)

    8.1. [The Spring Boot Starter for Credentials Support](#the-spring-boot-starter-for-credentials-support)

9. [**OpenSAML Support**](#opensaml-support)

10. [**Nimbus Support**](#nimbus-support)

11. [**PKCS#11 Specifics**](#pkcs11-specifics)

    11.1. [**Using SoftHSM to Test PKCS#11 Credentials**](#using-softhsm-to-test-pkcs11-credentials)

    11.2. [**Key Generation Scripts**](#key-generation-scripts)

---

<a name="overview"></a>
## 1. Overview

The **credentials-support** library defines an uniform way of representing PKI credentials (private keys and X.509 certificates) by introducing the [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) interface.

The library supports both basic credentials stored on file, or in a key store (JKS, PKCS#12), as well as PKCS#11 credentials residing on a Hardware Security Module.

The **credentials-support-nimbus** library offers support for working with [Nimbus](https://connect2id.com/products/nimbus-jose-jwt) datatypes such as the [JWK](https://connect2id.com/products/nimbus-jose-jwt/examples/jwk-generation) class in conjunction with [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) objects.

The **credentials-support-opensaml** library offers an add-on for OpenSAML, where a [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) object can be used to create an OpenSAML credential.

The **credentials-support-spring** library offers Spring add-ons consisting of converters, factories and configuration support.

The **credentials-support-spring-boot-starter** library is a Spring Boot starter that can be used for an easy and straight forward way of configuring credentials that are to be used in a Spring Boot application.

<a name="api-documentation"></a>
### 1.1. API Documentation

* [Java API documentation](https://docs.swedenconnect.se/credentials-support/apidoc/index.html)

<a name="maven"></a>
### 1.2. Maven

All libraries for the credentials-support project is published to Maven central.

Include the following snippets in your Maven POM to add dependencies for your project.

The **credentials-support** base library:

```
<dependency>
  <groupId>se.swedenconnect.security</groupId>
  <artifactId>credentials-support</artifactId>
  <version>${credentials-support.version}</version>
</dependency>
```

The **credentials-support-opensaml** library:

```
<dependency>
  <groupId>se.swedenconnect.security</groupId>
  <artifactId>credentials-support-opensaml</artifactId>
  <version>${credentials-support.version}</version>
</dependency>
```

> Will include the **opensaml-library**.

The **credentials-support-nimbus** library:

```
<dependency>
  <groupId>se.swedenconnect.security</groupId>
  <artifactId>credentials-support-nimbus</artifactId>
  <version>${credentials-support.version}</version>
</dependency>
```

> Will include the **opensaml-library**.

The **credentials-support-spring** library:

```
<dependency>
  <groupId>se.swedenconnect.security</groupId>
  <artifactId>credentials-support-spring</artifactId>
  <version>${credentials-support.version}</version>
</dependency>
```

> Will include the **opensaml-library**.

The **credentials-support-spring-boot-starter** library:

```
<dependency>
  <groupId>se.swedenconnect.security</groupId>
  <artifactId>credentials-support-spring-boot-starter</artifactId>
  <version>${credentials-support.version}</version>
</dependency>
```

> Will include **opensaml-library** and **credentials-support-spring**.


<a name="credential-types"></a>
## 2. Credential Types

The **credentials-support** library defines three classes implementing the [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) interface and a wrapper that takes a [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) into an OpenSAML credential type.

<a name="basiccredential"></a>
### 2.1. BasicCredential

The [BasicCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/BasicCredential.java) class is a simple implementation of the [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) interface that is created by providing the private key and certificate (or just a public key). This class can for example be used when you have the key and certificate stored on file.

<a name="keystorecredential"></a>
### 2.2. KeyStoreCredential

The [KeyStoreCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/KeyStoreCredential.java) class is backed by a Java KeyStore and is initialized by providing a loaded KeyStore instance (see [KeyStore Builder and Factory](#keystore-builder-and-factory) below) and giving the entry alias and key password. 

This class also supports handling of PKCS#11 credentials. This requires using a security provider that supports creating a KeyStore based on an underlying PKCS#11 implementation (for example the SunPKCS11 provider).

:exclamation: For a PKCS#11 key store, the `alias` parameter is equal to the PKCS#11 `CKA_LABEL` attribute for the object holding the private key (and certificate), and the `password` parameter is the PIN needed to unlock the object.

**Note:** If you are using a security provider for PKCS#11 support that does not support exposing the HSM device as a Java KeyStore, you need to use the [Pkcs11Credential](#pkcs11credential) (see below).

<a name="pkcs11credential"></a>
### 2.3. Pkcs11Credential

As was described above, the [KeyStoreCredential](#keystorecredential) can be used for PKCS#11 credentials, but it is limited to those Java security providers that also offers a KeyStore abstraction of the PKCS#11 device entry. The [Pkcs11Credential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/pkcs11/Pkcs11Credential.java) is a class that does not make any assumptions on how the security provider in use handles its PKCS#11 entries. Instead it uses the [Pkcs11Configuration](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/pkcs11/Pkcs11Configuration.java),
[Pkcs11PrivateKeyAccessor](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/pkcs11/Pkcs11PrivateKeyAccessor.java) and [Pkcs11CertificatesAccessor](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/pkcs11/Pkcs11CertificatesAccessor.java) interfaces.

The [Pkcs11Configuration](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/pkcs11/Pkcs11Configuration.java) interface declares the method `getProvider()` that returns the Java Security Provider that should be used for the PKCS#11 credential, and the accessors provide access to the private key and certificates respectively.

So, for those that wishes to use the **credentials-support** library with a custom security provider there is an implementation task ahead...

> The **credentials-support** library also offers implementation of the above interfaces for providers that uses key stores for PKCS#11 (SunPKCS11 provider). However, if you are using the SunPKCS11 provider stick with the [KeyStoreCredential](#keystorecredential).

<a name="pkicredential-features"></a>
## 3. PkiCredential Features

The main use of a [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) is to provide an abstraction and unified way of holding a private key and a certificate (or just a public key) for use in signing and decryption.

This section highlights some interesting features apart from getter-methods for keys and certificates.

<a name="credential-name"></a>
### 3.1. Credential Name

In an application where multiple credentials are used, we may want to have a way to name each credential (for logging and other purposes). Therefore, the `getName()` method exists, and the [AbstractPkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/AbstractPkiCredential.java) offers a way of assigning a custom name to a credential.

If no name is explicitly assigned, a name will be generated according to the following:

- For a [BasicCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/BasicCredential.java) the serial numver of the entity certificate will be used. If no certificate exists, the name will be chosen as \<public-key-type\>-\<uuid\>, for example, `RSA-0c6fbdce-b485-44a4-9000-93943626c675`.

- For a [KeyStoreCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/KeyStoreCredential.java) the following rules apply:
    - If the key store is a PKCS#11 key store, the name is \<provider name\>-\<alias\>-\<certificate serial number\>, for example `SunPKCS11-foo-rsa1-89716151`. Note that the provider name most usually is "base provider name"-"slot name".
    
    - For other key store types, the name is \<key type\>-\<alias\>-\<certificate serial number\>, for example `RSA-rsa1-89716151`.
    
- For a [Pkcs11Credential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/pkcs11/Pkcs11Credential.java) the name is calculated as \<provider-name\>-\<alias\>.

:raised_hand: It is recommended that a custom name is assigned to each credential to get a good understanding of which credential is which when looking at the logs. Make sure to use unique names.

<a name="transformation-to-other-formats"></a>
### 3.2. Transformation to other Formats

The **credentials-support** libraries offer a uniform way of representing credentials via the [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) interface and also a smooth and efficient way of configuring those (see section [5](credential-bundles-and-configuration-support) below), but other frameworks and libraries have their way of representing credentials. So, we need a way to handle this. The solution is the `tranform` method:

```java
/**
 * Transforms the credential to another format, for example an JWK or a Java KeyPair.
 *
 * @param transformFunction the transform function
 * @param <T> the type of the new format
 * @return the new format
 */
default <T> T transform(@Nonnull final Function<PkiCredential, T> transformFunction) {
  return transformFunction.apply(this);
}
```

Thus, by implementing a `Function` that accepts a [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) and returns the custom credential representation we can use the **credentials-support** library together with other frameworks.

See section [10](#nimbus-support), [Nimbus Support](#nimbus-support), for how to transform a [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) into a [JWK](https://javadoc.io/doc/com.nimbusds/nimbus-jose-jwt/latest/com/nimbusds/jose/jwk/JWK.html) and section [11](#opensaml-support), [OpenSAML Support](#opensaml-support), for how to transform a [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) into an OpenSAML [X509Credential](https://shibboleth.net/api/java-opensaml/5.1.3/org/opensaml/security/x509/X509Credential.html).


<a name="testing-and-reloading"></a>
### 3.3. Testing and Reloading

When using a HSM there is a possibility that the connection with the device is lost. The result is that the instantiated credential stops working. Therefore the **credentials-support** library offers ways to test and reload credentials. The credential types that support testing and reloading implements the [ReloadablePkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/ReloadablePkiCredential.java) interface.

An application that makes use of credentials that may fail, and may need to be reloaded, needs to set up a monitor that periodically tests that all monitored credentials are functional, and if not, tries to reload them. See section [6](#monitoring), [Monitoring](#monitoring), below.

For credentials implementing the [ReloadablePkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/ReloadablePkiCredential.java), the [DefaultCredentialTestFunction](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/monitoring/DefaultCredentialTestFunction.java) will be installed by default.

<a name="credential-metadata"></a>
### 3.4. Credential Metadata

Additional metadata may be associated with a credential. This is mainly useful when transforming to other formats, see section [3.2](#transformation-to-other-formats) above. The [PkiCredential.Metadata](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) interface is basically a map where metadata is stored.

The [AbstractPkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/AbstractPkiCredential.java) class will pre-populate the `issued-at` and `expires-at` based on the validity of a credential's entity certificate.

<a name="builders-and-factories"></a>
## 4. Builders and Factories

The libraries offer a number of builder and factory classes for building [KeyStore](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/KeyStore.html) and [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) objects.

<a name="keystore-builder-and-factories"></a>
### 4.1. KeyStore Builder and Factories

Setting up a Java [KeyStore](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/KeyStore.html) involves loading a file from disc and unlocking it. 

The [KeyStoreBuilder](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/factory/KeyStoreBuilder.java) class offers doing this using a standard builder pattern.

To load a Java KeyStore from file and to unlock it may then be done like:

```java
final KeyStore keyStore = KeyStoreBuilder.builder()
    .location("classpath:store.jks")
    .password("secret")
    .build();
```

> Note: The default resource loader will support strings with prefixes defined by Spring and [SmallRye](https://smallrye.io) (Qurkus style).

Example of how a PKCS#12 file is loaded.

```java
final KeyStore keyStore = KeyStoreBuilder.builder()
    .location("/opt/keys/mykeys.p12")
    .password("secret")
    .type("PKCS12")
    .build();
```

It is also possible to use the builder to load a PKCS#11 KeyStore:

```java
final KeyStore keyStore = KeyStoreBuilder.builder(new DefaultConfigurationResourceLoader())
    .type("PKCS11")
    .provider("SunPKCS11")
    .pin("secret")
    .pkcs11ConfigurationFile("/opt/config/p11.conf")
    .build();
```

Apart from the nice builder the class [KeyStoreFactory](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/factory/KeyStoreFactory.java) offers methods for loading a KeyStore. This class is mainly used internally when a [StoreConfiguration](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/config/StoreConfiguration.java) object should be turned into a KeyStore. See section [5.2.2](#key-store-configurations), [Key Store Configurations](#key-store-configurations), below.

<a name="credential-factories"></a>
### 4.2. Credential Factories

<a name="credential-bundles-and-configuration-support"></a>
## 5. Credential Bundles and Configuration Support

<a name="the-bundles-concept"></a>
### 5.1. The Bundles Concept

<a name="configuration-support"></a>
### 5.2. Configuration Support

<a name="basic-configuration-concepts"></a>
#### 5.2.1. Basic Configuration Concepts

<a name="key-store-configurations"></a>
#### 5.2.2. Key Store Configurations

<a name="spring-boot-configuration-support"></a>
### 5.3. Spring Boot Configuration Support

<a name="monitoring"></a>
## 6. Monitoring

<a name="credential-containers"></a>
## 7. Credential Containers for Managing Keys

This library provides support for setting up a credential container for generating, storing and managing public and private key pairs.

The primary use case for the credential container is when key pairs for user accounts are generated and maintained by an application and these keys are generated and stored in a HSM slot.  A typical such usage is when a signing service needs to generate a signing key for a document signer (user), and where this key is used to sign a document and then permanently deleted/destroyed without ever leaving the HSM.

Such procedure is necessary for the highest level of confidence that the signing key is kept under so called "sole-control" in accordance with the eIDAS regulation, which ensures that the key can never be copied or used by any other process or person to sign any other document under another identity.

Even though the HSM option is the primary use case, the credential container also supports software based or in-memory key storage.

<a name="creating-a-credential-container"></a>
### 7.1. Creating a Credential Container

A credential container is created according to the following examples:

<a name="hsm-based-credential-container"></a>
#### 7.1.1. HSM-based Credential Containers

A credential container backed up by a HSM via the PKCS#11 interface is implemented by the [HsmPkiCredentialContainer](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/container/HsmPkiCredentialContainer.java) class.

```java
final PkiCredentialContainer credentialContainer = new HsmPkiCredentialContainer(provider, hsmSlotPin);
```

The `provider` parameter is the security provider that implements the HSM slot‚ and the `hsmSlotPin` is the PIN code for accessing the HSM slot.

Instead of supplying a provider for the HSM slot as input, you may instead provide a `Pkcs11Configuration` object:

```java
final Pkcs11Configuration pkcs11Configuration = ...
final PkiCredentialContainer credentialContainer =
    new HsmPkiCredentialContainer(pkcs11Configuration, hsmSlotPin);
```

In most cases, the connection to the HSM-device is configured using a PKCS#11 configuration file, and
a `HsmPkiCredentialContainer` may be initialized by giving the full path to such a file.

```java
final String p11ConfigFile = "/opt/config/p11/hsm.cfg";
final PkiCredentialContainer credentialContainer = 
    new HsmPkiCredentialContainer(p11ConfigFile, hsmSlotPin);
```

<a name="in-memory-keystore-based-credential-container"></a>
#### 7.1.2. In-memory KeyStore-based Credential Container

The above example uses a Java [KeyStore](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/KeyStore.html) to maintain the keys/credentials in the HSM, but it is also possible to use a container that uses a [KeyStore](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/KeyStore.html) that resides in memory. The [SoftPkiCredentialContainer](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/container/SoftPkiCredentialContainer.java) class is mainly intended to mimic the behaviour of `HsmPkiCredentialContainer` and may be used in tests and simulations. See [7.1.3](#in-memory-based-credential-container) below for an in-memory credential container that does not go the detour via KeyStore-usage.

An in-memory KeyStore-based credential container is created as follows:

```java
final PkiCredentialContainer credentialContainer = new SoftPkiCredentialContainer(provider);
```

The `provider` parameter is either a Java Security Provider, or the name of the security provider. This provider is used to create the key store used to store keys as well as the provider used to generate keys.

<a name="in-memory-credential-container"></a>
#### 7.1.3. In-memory Credential Container

In order to use an in-memory based credential container create an instance of [InMemoryPkiCredentialContainer](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/container/InMemoryPkiCredentialContainer.java) as follows:

```java
final InMemoryPkiCredentialContainer credentialsContainer = new InMemoryPkiCredentialContainer(provider);
```

The `provider` parameter is either a Java Security Provider, or the name of the security provider. This provider is used to create the key store used to store keys as well as the provider used to generate
keys.

<a name="using-the-credential-container"></a>
### 7.2. Using the Credential Container

Keys are generated in the credential container by calling the method `generateCredential(keyType)`, 
where `keyType` is a string representing an algorithm and key type, see [KeyGenType](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/container/keytype/KeyGenType.java).

**Example:** Generating a Nist P-256 EC key pair:

```
final String alias = credentialContainer.generateCredential(KeyGenType.EC_P256);
```

The returned alias is the handle used to obtain a [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) object for the newly generated key pair.

```
final PkiCredential credential = credentialContainer.getCredential(alias);
```

**Destroying credentials after use**

The [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) objects returned from the credential container have extended capabilities to ensure that the private key is destroyed when calling the `destroy()` method of the `PkiCredential` object.

In order to ensure that private keys are properly removed after usage, implementations should:

1. Create keys with as short validity time as possible.<sup>*</sup>
2. On all restarts and on suitable occasions, call the `cleanup()` method to ensure that old keys are properly deleted.<sup>**</sup>
3. Always call the `destroy()` method immediately after its last intended use.

> \[\*\]: The validity time of a key pair (credential) is 15 minutes by default. It can be changed
using the `setKeyValidity` method on the container.

> \[\*\*\]: It is also wise to schedule a task that periodically invokes the `cleanup()` method of the container in use. By doing so we ensure that generated keys are not left too long in the container (expired credentials will be purged).
    
<a name="spring-support"></a>
## 8. Spring Support

<a name="the-spring-boot-starter-for-credentials-support"></a>
### 8.1. The Spring Boot Starter for Credentials Support

<a name="opensaml-support"></a>
## 9. OpenSAML Support

<a name="nimbus-support"></a>
## 10. Nimbus Support

<a name="pkcs11-specifics"></a>
## 11. PKCS#11 Specifics

<a name="using-softhsm-to-test-pkcs11-credentials"></a>
### 11.1. Using SoftHSM to Test PKCS#11 Credentials

[SoftHSM](https://wiki.opendnssec.org/display/SoftHSMDOCS) is a great way to test your PKCS#11 credentials without an actual HSM. The **credentials-support** library contains a simple Spring Boot app that illustrates how to set up SoftHSM and how to configure your PKCS#11 devices, see the [softhsm](https://github.com/swedenconnect/credentials-support/tree/main/softhsm) directory for details.

Once you have an application that is setup to use credentials from an HSM, this library also includes a set of scripts that extends a docker image with SoftHSM support. These scripts and their usage is described in [hsm-support-scripts/soft-hsm-deployment/README.md](https://github.com/swedenconnect/credentials-support/blob/main/hsm-support-scripts/soft-hsm-deployment/README.md).

<a name="key-generation-scripts"></a>
### 11.2. Key Generation Scripts

In order to support generation and installing of keys and key certificates in any HSM device as part of setting up a production environment, this repository also provides some supporting key generation scripts:

- A PKCS11 key generation script (p11-keygen.sh) used to generate keys and install certificates in a HSM slot.
- A corresponding soft key generation script that will create key stores (JKS and PKCS12) to support test environment setup.

For further information consult the information at [hsm-support-scripts/key-generation/README.md](https://github.com/swedenconnect/credentials-support/blob/main/hsm-support-scripts/key-generation/README.md)


---

Copyright &copy; 2020-2024, [Sweden Connect](https://swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).