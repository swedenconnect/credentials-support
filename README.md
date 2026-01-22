![Logo](https://docs.swedenconnect.se/technical-framework/img/sweden-connect.png)

# credentials-support

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) ![Maven Central](https://img.shields.io/maven-central/v/se.swedenconnect.security/credentials-support.svg)

Java libraries for PKI credentials support, including PKCS#11 and HSM:s.

---

## Table of contents

1. [**Overview**](#overview)

    1.1. [API Documentation](#api-documentation)
    
    1.2. [Maven](#maven)
    
    1.3. [Release Notes](#release-notes)
    
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

5. [**Credential Bundles, Collections and Configuration Support**](#credential-bundles-collections-and-configuration-support)

    5.1. [The Bundles Concept](#the-bundles-concept)
    
    5.2. [PkiCredentialCollection](#pki-credential-collection)
    
    5.3. [Configuration Support](#configuration-support)
    
    5.3.1. [StoreConfigurationProperties](#store-configuration-properties)
    
    5.3.2. [BaseCredentialConfigurationProperties](#base-credential-configuration-properties)

    5.3.3. [PemCredentialConfigurationProperties](#pem-credential-configuration-properties)
    
    5.3.4. [StoreCredentialConfigurationProperties](#store-credential-configuration-properties)

    5.3.5. [PkiCredentialConfigurationProperties](#pki-credential-configuration-properties)

    5.3.6. [CredentialBundlesConfigurationProperties](#credential-bundles-configuration-properties)

    5.3.7. [PkiCredentialCollectionConfigurationProperties](#pki-credential-collection-configuration-properties)
    
    5.3.8. [SpringCredentialConfigurationProperties](#spring-credential-configuration-properties)
    
6. [**Monitoring**](#monitoring)

7. [**Credential Containers for Managing Keys**](#credential-containers)

    7.1. [Creating a Credential Container](#creating-a-credential-container)
    
    7.1.1. [HSM-based Credential Containers](#hsm-based-credential-container)
    
    7.1.2. [In-memory KeyStore-based Credential Container](#in-memory-keystore-based-credential-container)
    
    7.1.3. [In-memory Credential Container](#in-memory-credential-container)
    
    7.2. [Using the Credential Container](#using-the-credential-container)
    
8. [**Spring Support**](#spring-support)

    8.1. [Spring Factories](#spring-factories)

    8.2. [Spring Converters](#spring-converters)

    8.3. [The Spring Boot Starter for Credentials Support](#the-spring-boot-starter-for-credentials-support)
    
    8.3.1. [Credential Monitoring Health Endpoint](#credential-monitoring-health-endpoint)

9. [**OpenSAML Support**](#opensaml-support)

10. [**Nimbus Support**](#nimbus-support)

11. [**PKCS#11 Specifics**](#pkcs11-specifics)

    11.1. [Using SoftHSM to Test PKCS#11 Credentials](#using-softhsm-to-test-pkcs11-credentials)

    11.2. [Key Generation Scripts](#key-generation-scripts)

---

<a name="overview"></a>
## 1. Overview

The **credentials-support** library defines an uniform way of representing PKI credentials (private keys and X.509 certificates) by introducing the [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) interface.

The library supports both basic credentials stored on file, or in a key store (JKS, PKCS#12), as well as PKCS#11 credentials residing on a Hardware Security Module.

The **credentials-support-nimbus** library offers support for working with [Nimbus](https://connect2id.com/products/nimbus-jose-jwt) datatypes such as the [JWK](https://connect2id.com/products/nimbus-jose-jwt/examples/jwk-generation) class in conjunction with [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) objects.

The **credentials-support-opensaml** library offers an add-on for OpenSAML, where a [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) object can be used to create an OpenSAML credential.

The **credentials-support-spring** library offers Spring add-ons consisting of converters, factories and configuration support.

The **credentials-support-spring-boot-starter** library is a Spring Boot starter that can be used for an easy and straight forward way of configuring credentials that are to be used in a Spring Boot application.


<a name="generic-pkicredentialfactorybean-for-springboot-users"></a>
:exclamation: If you are still using the 1.X.X version of the **credentials-support** library, see the [old README](https://docs.swedenconnect.se/credentials-support/old-readme.html).

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

<a name="release-notes"></a>
### 1.3. Release Notes

See https://docs.swedenconnect.se/credentials-support/release-notes.html

<a name="credential-types"></a>
## 2. Credential Types

The **credentials-support** library defines three classes implementing the [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) interface and a wrapper that takes a [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) into an OpenSAML credential type.

<a name="basiccredential"></a>
### 2.1. BasicCredential

The [BasicCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/BasicCredential.java) class is a simple implementation of the [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) interface that is created by providing the private key and certificate (or just a public key). This class can for example be used when you have the key and certificate stored on file or in memory.

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
    - If the key store is a PKCS#11 key store, the name is `<provider name>-<alias>-<certificate serial number>`, for example `SunPKCS11-foo-rsa1-89716151`. Note that the provider name most usually is "base provider name"-"slot name".
    
    - For other key store types, the name is `<key type>-<alias>-<certificate serial number>`, for example `RSA-mykey-89716151`.
    
- For a [Pkcs11Credential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/pkcs11/Pkcs11Credential.java) the name is calculated as `<provider-name>-<alias>`.

:raised_hand: It is recommended that a custom name is assigned to each credential to get a good understanding of which credential is which when looking at the logs. Make sure to use unique names.

<a name="transformation-to-other-formats"></a>
### 3.2. Transformation to other Formats

The **credentials-support** libraries offer a uniform way of representing credentials via the [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) interface and also a smooth and efficient way of configuring those (see [Section 5](credential-bundles-collections-and-configuration-support) below), but other frameworks and libraries have their way of representing credentials. So, we need a way to handle this. The solution is the `tranform` method:

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

See [Section 10, Nimbus Support](#nimbus-support), for how to transform a [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) into a [JWK](https://javadoc.io/doc/com.nimbusds/nimbus-jose-jwt/latest/com/nimbusds/jose/jwk/JWK.html) and [Section 11, OpenSAML Support](#opensaml-support), for how to transform a [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) into an OpenSAML [X509Credential](https://shibboleth.net/api/java-opensaml/5.1.3/org/opensaml/security/x509/X509Credential.html).


<a name="testing-and-reloading"></a>
### 3.3. Testing and Reloading

When using a HSM there is a possibility that the connection with the device is lost. The result is that the instantiated credential stops working. Therefore the **credentials-support** library offers ways to test and reload credentials. The credential types that support testing and reloading implements the [ReloadablePkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/ReloadablePkiCredential.java) interface.

An application that makes use of credentials that may fail, and may need to be reloaded, needs to set up a monitor that periodically tests that all monitored credentials are functional, and if not, tries to reload them. See [Section 6, Monitoring](#monitoring) below.

For credentials implementing the [ReloadablePkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/ReloadablePkiCredential.java), the [DefaultCredentialTestFunction](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/monitoring/DefaultCredentialTestFunction.java) will be installed by default.

<a name="credential-metadata"></a>
### 3.4. Credential Metadata

Additional metadata may be associated with a credential. This is mainly useful when transforming to other formats, see [Section 3.2](#transformation-to-other-formats), or when storing credentials in a [PkiCredentialCollection](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredentialCollection.java), see [Section 5.2](#pki-credential-collection).

The [PkiCredential.Metadata](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) interface is basically a map where metadata is stored.

The following metadata properties are pre-defined:

- `key-id` - Property name for the key identifier metadata property.

- `issued-at` - Property name for the instant when the credential was issued.

- `expires-at` - Property name for the instant when the credential expires. Note that this may be different from the instant holding the `active-to` property.

- `active-to` - Property that may be set to the instant at which the credential no longer should be regarded as active.

- `active-from` - Property that may be set to the instant from when the credential should be regarded as active.

- `usage` - Property name for the usage property. This property holds a string that may be `signing`, `encryption`, `metadata-signing` or any other application specific usage.

- `key-use` - \[Nimbus specific\] - Property name for the key use metadata property. Maps to JWK's `use` property. Prefer to use the generic `usage` setting.

- `key-ops` - \[Nimbus specific\] - Property name for the key operations metadata property. Maps to JWK's `ops` property. Should hold a set of [KeyOperation](https://javadoc.io/doc/com.nimbusds/nimbus-jose-jwt/latest/com/nimbusds/jose/jwk/KeyOperation.html) objects or a comma-separated list of strings.

- `jose-alg`- \[Nimbus specific\] - Property name for the JOSE algorithm metadata property. Maps to JWK's `alg` property. Should hold a [Algorithm](https://javadoc.io/doc/com.nimbusds/nimbus-jose-jwt/latest/com/nimbusds/jose/Algorithm.html) or its string representation.

- `entity-id` - \[OpenSAML specific\] - Property name for assigning a SAML entity ID to the credential metadata.

- `encryption-methods` - \[OpenSAML specific\] - Property name for holding `md:EncryptionMethod` data. See [EncryptionMethodMetadata](https://github.com/swedenconnect/credentials-support/blob/main/opensaml/src/main/java/se/swedenconnect/security/credential/opensaml/EncryptionMethodMetadata.java).

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
final KeyStore keyStore = KeyStoreBuilder.builder(customResourceLoader)
    .type("PKCS11")
    .provider("SunPKCS11")
    .pin("secret")
    .pkcs11ConfigurationFile("/opt/config/p11.conf")
    .build();
```

The example above illustrates how another resource loader is used. For Spring users, the [SpringConfigurationResourceLoader](https://github.com/swedenconnect/credentials-support/blob/main/spring/credentials-support-spring/src/main/java/se/swedenconnect/security/credential/spring/config/SpringConfigurationResourceLoader.java) should be used.

Apart from the nice builder the class [KeyStoreFactory](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/factory/KeyStoreFactory.java) offers methods for loading a KeyStore. This class is mainly used internally when a [StoreConfiguration](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/config/StoreConfiguration.java) object should be turned into a KeyStore. See [Section 5.3](#configuration-support) below.

See also [Section 8.1, Spring Factories](#spring-factories).

<a name="credential-factories"></a>
### 4.2. Credential Factories

Creating a [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) instance is easiest done using the different constructors for [BasicCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/BasicCredential.java) or [KeyStoreCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/KeyStoreCredential.java), but the **credentials-support** also offers the [PkiCredentialFactory](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/factory/PkiCredentialFactory.java). This class is mainly intended to be used internally when loading configuration (see [Section 5.3](#configuration-support)) below.

See also [Section 8.1, Spring Factories](#spring-factories).

<a name="credential-bundles-collections-and-configuration-support"></a>
## 5. Credential Bundles, Collections and Configuration Support

<a name="the-bundles-concept"></a>
### 5.1. The Bundles Concept

Spring Boot has introduced a feature called [SSL Bundles](https://docs.spring.io/spring-boot/reference/features/ssl.html) where SSL/TLS credentials are configured in a separate place, and later referenced in different location where they are needed.

```yaml
spring:
  ssl:
    bundle:
      jks:
        mybundle:
          key:
            alias: "application"
          keystore:
            location: "classpath:application.p12"
            password: "secret"
            type: "PKCS12"
            
myapp:
  example:
    bundle: mybundle
```

The **credentials-support** library borrows/steals this concept and introduces "Credential Bundles", where [KeyStore](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/KeyStore.html) and [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) instances are configured under a bundle, and then referenced wherever they are needed.

Example:

```
credential:
  bundles:
    keystore:
      ks1:
        location: classpath:ks-1.jks
        password: secret
        type: JKS
    jks:
      cred1:
        store-reference: ks1
        name: "Credential One"
        key:
          alias: rsa1
          key-password: secret
      cred2:
        store-reference: ks1
        name: "Credential Two"
        key:
          alias: rsa2
          key-password: secret
    pem:
      cred3:
        certificates: file:/opt/creds/cred3.pem.crt
        private-key: file:/opt/creds/cred3.pkcs8.key
        name: "Credential Three"
        
myapp:
  example:
    credential: cred2
```

The package [se.swedenconnect.security.credential.bundle](https://github.com/swedenconnect/credentials-support/tree/main/credentials-support/src/main/java/se/swedenconnect/security/credential/bundle) contains support for implementing "Credential Bundles". It contains the following interfaces and classes:

- [CredentialBundles](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/bundle/CredentialBundles.java) - An interface for accessing registered credentials and keystores. 

- [CredentialBundleRegistry](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/bundle/CredentialBundleRegistry.java) - An interface for registering [KeyStore](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/KeyStore.html) and [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) instances in the credential bundle.

- [CredentialBundleRegistrar](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/bundle/CredentialBundleRegistrar.java) - A functional interface for registering stores and credentials at a [CredentialBundleRegistry](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/bundle/CredentialBundleRegistry.java).

- [DefaultCredentialBundleRegistry](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/bundle/DefaultCredentialBundleRegistry.java) - Default implementation of the [CredentialBundles](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/bundle/CredentialBundles.java) and [CredentialBundleRegistry](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/bundle/CredentialBundleRegistry.java) interfaces.

- [ConfigurationCredentialBundleRegistrar](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/bundle/ConfigurationCredentialBundleRegistrar.java) - An implementation of the [CredentialBundleRegistrar](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/bundle/CredentialBundleRegistrar.java) interface that sets up a [CredentialBundles](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/bundle/CredentialBundles.java) based on the a supplied [CredentialBundlesConfiguration](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/config/CredentialBundlesConfiguration.java) (see [Section 5.3](#configuration-support) below).

The below example shows how a [CredentialBundles](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/bundle/CredentialBundles.java) is constructed.

```java
final CredentialBundlesConfiguration config = ...;
final DefaultCredentialBundleRegistry bundle = new DefaultCredentialBundleRegistry();

final ConfigurationCredentialBundleRegistrar registrar =
    new ConfigurationCredentialBundleRegistrar(config);
registrar.register(bundle);
// bundle is now populated with all stores and credentials available from the configuration object.
```

:raised_hand: When using the Spring Boot Starter, a fully populated [CredentialBundles](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/bundle/CredentialBundles.java) bean will be injected automatically based on the credentials configuration. See [Section 8.3, The Spring Boot Starter for Credentials Support](#the-spring-boot-starter-for-credentials-support).

Once a [CredentialBundles](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/bundle/CredentialBundles.java) object has been set up, it can be queried for registered keystores and credentials.

```java
final CredentialBundles bundles = ...;

final PkiCredential credential1 = bundles.getCredential("cred1");
```

<a name="pki-credential-collection"></a>
### 5.2. PkiCredentialCollection

The [PkiCredentialCollection](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredentialCollection.java) class is intended for applications that need to configure several credentials, for example a SAML Identity Provider that has a signature key, an encryption key and possibly other keys.

By using any of the pre-defined [Predicate](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/util/function/Predicate.html)s, or by supplying a custom [Predicate](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/util/function/Predicate.html), a specific credential is returned from the collection.

The pre-defined [Predicate](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/util/function/Predicate.html)s are:

- `isRsa` - Predicate that tells whether a credential holds an RSA key.

- `isEc` - Predicate that tells whether a credential holds an EC key.

- `isHardwareCredential` - Predicate that tells whether a credential is a hardware credential, i.e., stored on an HSM.

- `keyId(id)` - Method that returns a Predicate that checks if a credential has a given key ID.

- `usage(u)` - Method that returns a Predicate that checks if a credential has a given usage.

- `signatureUsage` - Predicate that checks if the credential has the `signing` usage.

- `encryptionUsage` - Predicate that checks if the credential has the `encryption` usage.

- `unspecifiedUsage` - Predicate that checks if the credential does not have a specified usage.

- `isActive` - Predicate that checks if the credential is "active", meaning that the current time is within the `active-from` and `active-to` properties. If no such properties are set, the credential is assumed to be active.

- `noLongerActive` - Predicate that checks if the credential is no longer active, meaning that the `active-to` metadata setting is before the current time.

- `isNotYetActive` - Predicate that tells whether the credential is "not yet active", meaning that the `active-from` metadata setting is after the current time.

- `forFutureSigning` - Predicate that tells if a credential is intended to be the signing credential in the future. It is a combination of `signatureUsage` and `isNotYetActive`.

<a name="configuration-support"></a>
### 5.3. Configuration Support

The package [se.swedenconnect.security.credential.config](https://github.com/swedenconnect/credentials-support/tree/main/credentials-support/src/main/java/se/swedenconnect/security/credential/config) contains interfaces for configuring [KeyStore](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/KeyStore.html) and [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) instances.

Each interface also has a corresponding implementation class under the [se.swedenconnect.security.credential.config.properties](https://github.com/swedenconnect/credentials-support/tree/main/credentials-support/src/main/java/se/swedenconnect/security/credential/config/properties) package.

The reason that interfaces are used is that we want to make it possible to use the [SmallRye Configuration Library](https://smallrye.io/smallrye-config/) to configure keystores and credentials. For Spring use, the corresponding concrete classes are used.

The following configuration interfaces and classes are available:

| Interface | Class | Description |
| :--- | :--- | :--- |
| [StoreConfiguration](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/config/StoreConfiguration.java) | [StoreConfigurationProperties](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/config/properties/StoreConfigurationProperties.java) | Configuration for creating a [KeyStore](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/KeyStore.html). This includes configuration support for configuring a PKCS#11 [KeyStore](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/KeyStore.html).<br />See [5.3.1](#store-configuration-properties). |
| [PemCredentialConfiguration](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/config/PemCredentialConfiguration.java) | [PemCredentialConfigurationProperties](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/config/properties/PemCredentialConfigurationProperties.java) | Configuration for creating a [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) using PEM-encoded certificate(s)/public keys and private keys. Both references to resources and inline PEM-encodings are supported.<br />See [5.3.3](#pem-credential-configuration-properties). |
| [StoreCredentialConfiguration](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/config/StoreCredentialConfiguration.java) | [StoreCredentialConfigurationProperties](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/config/properties/StoreCredentialConfigurationProperties.java) | Configuration for creating a [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) backed by a [KeyStore](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/KeyStore.html).<br />See [5.3.4](#store-credential-configuration-properties). |
| [PkiCredentialConfiguration](https://github.com/swedenconnect/credentials-support/main/credentials-support/src/main/java/se/swedenconnect/security/credential/config/PkiCredentialConfiguration.java) | [PkiCredentialConfigurationProperties](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/config/properties/PkiCredentialConfigurationProperties.java) | Configuration support for configuring a [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) outside of the bundles concept. One, and exactly one, of `bundle`, `jks` or `pem` must be supplied.<br />See [5.3.5](#pki-credential-configuration-properties). |
| [CredentialBundlesConfiguration](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/config/CredentialBundlesConfiguration.java) | [CredentialBundlesConfigurationProperties](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/config/properties/CredentialBundlesConfigurationProperties.java) | Configuration for bundles of credentials and keystores.<br />If both PEM and JKS (keystore) credentials are configured, the ID:s assigned must be unique for all credentials, i.e., the same ID can not be used for PEM and JKS.<br />See [5.3.6](#credential-bundles-configuration-properties). |

<a name="store-configuration-properties"></a>
#### 5.3.1. StoreConfigurationProperties

Configuration for creating a [KeyStore](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/KeyStore.html).

| Property | Description | Type |
| :--- | :--- | :--- |
| `location` | Location of the keystore. Spring and [SmallRye](https://smallrye.io/smallrye-config/) prefixes such as "classpath:" and "file:" are supported. For PKCS#11 keystores, this property should not be assigned. | String |
| `password` | The password for unlocking the keystore. | String |
| `type` | The type of keystore, e.g. "JKS", "PKCS12 or "PKCS11". | String |
| `provider` | The name of the Security provider to use when setting up the keystore. If not assigned, a system default will be used. | String |
| `pkcs11.*` | If the `type` is "PKCS11" and a provider that is not statically configured for PKCS#11, additional PKCS#11 configuration needs to be supplied. Note that the security provider used must support PKCS#11 via the KeyStoreSpi interface. The "SunPKCS11" is such a provider. | See [Pkcs11ConfigurationProperties](#pkcs11-configuration-properties) below |

<a name="pkcs11-configuration-properties"></a>
##### 5.2.1.1. Pkcs11ConfigurationProperties

Additional configuration of PKCS11 key stores.

| Property | Description | Type |
| :--- | :--- | :--- |
| `configuration-file` | The complete path of the PKCS#11 configuration file with which the PKCS#11 device is configured. | String |
| `settings.*` | As an alternative to providing the PKCS#11 configuration file, each PKCS#11 setting can be provided separately. This property holds these detailed settings. | See Pkcs11SettingsProperties below |

**Pkcs11SettingsProperties:**

| Property | Description | Type |
| :--- | :--- | :--- |
| `library` | The PKCS#11 library path. | String |
| `name` | The name of the PKCS#11 slot. | String |
| `slot` | The slot number/id to use. | String |
| `slot-list-index` | The slot index to use. | Integer |

<a name="base-credential-configuration-properties"></a>
#### 5.3.2. BaseCredentialConfigurationProperties

the [AbstractBaseCredentialConfigurationProperties](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/config/properties/AbstractBaseCredentialConfigurationProperties.java) class is a base class that is used by both [PemCredentialConfigurationProperties](#pem-credential-configuration-properties) and [StoreCredentialConfigurationProperties](#store-credential-configuration-properties). It defines properties that are common for all type of credentials.

| Property | Description | Type |
| :--- | :--- | :--- |
| `name` | The name of the credential. | String |
| `key-id` | Key identifier metadata property. | String |
| `issued-at` | Issued-at metadata property. | [Instant](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/time/Instant.html) |
| `expires-at` | Expires-at metadata property. | [Instant](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/time/Instant.html) |
| `metadata` | Additional metadata in the form of key-value:s | [Map](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/util/Map.html) where both keys and values are Strings |

<a name="pem-credential-configuration-properties"></a>
#### 5.3.3. PemCredentialConfigurationProperties

Configuration for creating a [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) using PEM-encoded certificate(s)/public keys and private keys. Both references to resources and inline PEM-encodings are supported.

In addition to the [BaseCredentialConfigurationProperties](#base-credential-configuration-properties) the following properties are used to configure a PEM-based credential:

| Property | Description | Type |
| :--- | :--- | :--- |
| `public-key` | Location or content of the public key in PEM format. This setting is mutually exclusive with the `certificates` setting. | String |
| `certificates` | Location or content of the certificate or certificate chain in PEM format. If more than one certificate is supplied, the entity certificate, i.e., the certificate holding the public key of the key pair, must be placed first. This setting is mutually exclusive with the `public-key` setting. | String |
| `private-key` | Location or content of the private key in PEM format. | String |
| `key-password` | Password used to decrypt the private key (if this is given in encrypted format). | String |

Examples illustrating how a PEM-based credential can be configured.

```yml
credential:
  bundles:
    ...
    pem:
      cred1:
        certificates: file:/opt/keys/test1.pem.crt
        private-key: file:/opt/keys/test1.pkcs8.key
        name: "Example credential #1"
```

```yml
credential:
  bundles:
    ...
    pem:
      cred2:
        certificates: |
          -----BEGIN CERTIFICATE-----
          MIIDFDCCAfygAwIBAgIEZyt6yTANBgkqhkiG9w0BAQsFADBMMQswCQYDVQQGEwJT
          RTEXMBUGA1UECgwOU3dlZGVuIENvbm5lY3QxFDASBgNVBAsMC0RldmVsb3BtZW50
          ...
          wVz5c0ouR+c54aoJn1oVg6PCga41gvEtc03Fl0W0vmxs0QZHg15g7Mugd4jQzi/9
          6mrCVbGyFIYkGi4vgVA+aMVYyyaSXKyN
          -----END CERTIFICATE-----
        private-key: |
          -----BEGIN PRIVATE KEY-----
          MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCX9V5RUFhAId1X
          JVBPYN0lWkV4sWrZuPzxRTYDdA5LNsLPXmu/lthjLk1RLYqxJidsywJWTzkNS3FU
          ...
          5MGCkA4SKlmCZFqyKq6W7Dxk+dz55VNoZNAKpYaPIex885cl1A6/7OxMt4V3Fp/Z
          gwfASW4la2qIv1z4fIuR4Tnz3uE7UXdfHJSBVr0D0fFf7JrOQV0lMx5wr3X4jcKQ
          6gE2jgKrhq3F/BbqbDEk7mTfHw==
          -----END PRIVATE KEY-----
        name: "Example credential #2"
```

<a name="store-credential-configuration-properties"></a>
#### 5.3.4. StoreCredentialConfigurationProperties

Configuration for creating a [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) backed by a [KeyStore](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/KeyStore.html).

In addition to the [BaseCredentialConfigurationProperties](#base-credential-configuration-properties) the following properties are used to configure a JKS-based credential:

| Property | Description | Type |
| :--- | :--- | :--- |
| `store` | Configuration for the [KeyStore](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/KeyStore.html) holding the key pair entry. Mutually exclusive with the `store-reference` property. | [StoreConfigurationProperties](#store-configuration-properties) |
| `store-reference` | A store reference. As an alternative to giving the key store configuration, a reference to a key store configuration may be given. This feature may be used when one key store holds several keys. Makes use of the [Bundles Concept](#the-bundles-concept). | String |
| `monitor` | Setting telling whether the credential should be configured for [monitoring](#monitoring). The default is `true` if the store used is a PKCS#11 store, and `false` otherwise. | Boolean |
| `key.alias` | The alias that identifies the key pair in the key store.<br />If the store is a PKCS#11 store, this setting corresponds to the PKCS#11 `CKA_LABEL` attribute for the object holding the private key on the device. | String |
| `key.key-password` | The password to unlock the key entry identified by the given alias. If not given, the store password will be used (in these cases, using a store reference will not function). | String |
| `key.certificates` | For some credentials where an underlying KeyStore is being used, an external certificate should be used. The most typical example would be a PKCS#11 key store where the certificate of the key pair resides outside the HSM device. This setting holds the location or content of the certificate or certificate chain in PEM format. | String |

Example:

```yml
credential:
  bundles:
    keystore:
      ks1:  
        ...
    jks:
      cred1:
        name: "Example credential #1"
        store-reference: ks1
        key:
          alias: test1
          key-password: secret
        monitor: true
        key-id: 123456
        issued-at: "2024-11-15T14:08:26Z"
        metadata:
          algorithm: RSA
          keyuse: sign
      cred2:
        name: "Example credential #2"
        store:
          location: file:/opt/keys/example.p12
          password: secret
          type: PKCS12
        key:
          alias: mykey
```

The above example illustrates how two JKS-credentials are configured. The first one refers to an already configured keystore and the other configures the store inline. Also note how metadata is configured for the first credential.

<a name="pki-credential-configuration-properties"></a>
#### 5.3.5. PkiCredentialConfigurationProperties

The [PkiCredentialConfigurationProperties](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/config/properties/PkiCredentialConfigurationProperties.java) is not used when setting up a credential using the [Bundles Concept](#the-bundles-concept). It is aimed to be used as the primary configuration object when a [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) is to be configured directly in an application.

| Property | Description | Type |
| :--- | :--- | :--- |
| `bundle` | Reference to a [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) accessible via the [CredentialBundles](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/bundle/CredentialBundles.java) bean. | String |
| `jks` | Configuration for a JKS (Java KeyStore) based credential. | [StoreCredentialConfigurationProperties](#store-credential-configuration-properties) |
| `pem` | Configuration for a PEM-based credential. | [PemCredentialConfigurationProperties](#pem-credential-configuration-properties) |

:exclamation: One, and exactly one, of `bundle`, `jks` or `pem` must be supplied.

Study the [TestConfigurationProperties](https://github.com/swedenconnect/credentials-support/blob/main/softhsm/src/main/java/se/swedenconnect/security/credential/test/TestConfigurationProperties.java) and [TestConfiguration](https://github.com/swedenconnect/credentials-support/blob/main/softhsm/src/main/java/se/swedenconnect/security/credential/test/TestConfiguration.java) in the application example for how a [PkiCredentialConfigurationProperties](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/config/properties/PkiCredentialConfigurationProperties.java) class can be used in an application's configuration to inject a credential (from a bundle or directly configured).

<a name="credential-bundles-configuration-properties"></a>
#### 5.3.6. CredentialBundlesConfigurationProperties

The [CredentialBundlesConfigurationProperties](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/config/properties/CredentialBundlesConfigurationProperties.java) class is the main configuration class for setting up a [CredentialBundles](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/bundle/CredentialBundles.java) bean (see [5.1](#the-bundles-concept) above).

| Property | Description | Type |
| :--- | :--- | :--- |
| `keystore` | Map of key store ID:s and key store configurations. | Map where keys are Strings (ID:s) and the values are [StoreConfigurationProperties](#store-configuration-properties). |
| `pem` | Map of credential ID:s and PEM based credential configurations. | Map where keys are Strings (ID:s) and the values are [PemCredentialConfigurationProperties](#pem-credential-configuration-properties). |
| `jks` | Map of credential ID:s and key store based credential configurations. | Map where keys are Strings (ID:s) and the values are [StoreCredentialConfigurationProperties](#store-credential-configuration-properties). |

:exclamation: If both PEM and JKS (keystore) credentials are configured, the ID:s assigned must be unique for all credentials, i.e., the same ID can not be used for PEM and JKS.

**Example:**

```yml
credential:
  bundles:
    keystore:
      ks1:
        location: file:/opt/keys/test-1.jks
        password: secret
        type: JKS
      p11:
        password: secret
        type: PKCS11
        provider: SunPKCS11
        pkcs11:
          configuration-file: /opt/config/p11.conf
    jks:
      test1:
        store-reference: ks1
        name: "Test1"
        key:
          alias: test1
          key-password: secret
        monitor: true
        key-id: 123456
        issued-at: "2024-11-15T14:08:26Z"
        metadata:
          algorithm: RSA
          keyuse: sign
      test2:
        store:
          location: classpath:test-2.p12
          password: secret
          type: PKCS12
        name: "Test2"
        key:
          alias: test2
      testP11:
        store-reference: p11
        name: "TestPkcs11"
        key:
          key-password: secret
          alias: test1
        monitor: true
    pem:
      test3:
        certificates: classpath:test3.pem.crt
        private-key: classpath:test3.pkcs8.key
        name: "Test3"
      test3b:
        public-key: classpath:test3.pubkey.pem
        private-key: classpath:test3.pkcs8.key
        name: "Test3b"
      test4:
        certificates: classpath:test4.pem.crt
        private-key: classpath:test4.pkcs8.enc.key
        key-password: secret
        name: "Test4"
      test5:
        certificates: |
          -----BEGIN CERTIFICATE-----
          MIIDFDCCAfygAwIBAgIEZyt6yTANBgkqhkiG9w0BAQsFADBMMQswCQYDVQQGEwJT
          RTEXMBUGA1UECgwOU3dlZGVuIENvbm5lY3QxFDASBgNVBAsMC0RldmVsb3BtZW50
          ...
          wVz5c0ouR+c54aoJn1oVg6PCga41gvEtc03Fl0W0vmxs0QZHg15g7Mugd4jQzi/9
          6mrCVbGyFIYkGi4vgVA+aMVYyyaSXKyN
          -----END CERTIFICATE-----
        private-key: |
          -----BEGIN PRIVATE KEY-----
          MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCX9V5RUFhAId1X
          JVBPYN0lWkV4sWrZuPzxRTYDdA5LNsLPXmu/lthjLk1RLYqxJidsywJWTzkNS3FU
          ...
          6gE2jgKrhq3F/BbqbDEk7mTfHw==
          -----END PRIVATE KEY-----
        name: "Test5"
```

<a name="pki-credential-collection-configuration-properties"></a>
#### 5.3.7. PkiCredentialCollectionConfigurationProperties

The [PkiCredentialCollectionConfigurationProperties](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/config/properties/PkiCredentialCollectionConfigurationProperties.java) class in the main configuration class for creating a [PkiCredentialCollection](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredentialCollection.java) bean (see [5.2](#pki-credential-collection) above).

| Property | Description | Type |
| :--- | :--- | :--- |
| `credentials` | A list of [PkiCredentialConfigurationProperties](#pki-credential-configuration-properties) objects. | List of [PkiCredentialConfigurationProperties](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/config/properties/PkiCredentialConfigurationProperties.java) |

**Example:**

```yml
credential:
  collection:
    bundles:
      jks:
        cred1:
          ...
    credentials:
      - bundle: cred1
      - jks:
          name: "IdP Signing"
          store:
            location: file:/opt/keys/example.p12
            password: secret
            type: PKCS12
          key:
            alias: signing
          usage: signing
```

The credentials of the collection can either refer to a bundle, or be configured "in place".

<a name="spring-credential-configuration-properties"></a>
#### 5.3.8. SpringCredentialConfigurationProperties

The Spring Boot Starter, as described in [Section 8.3](#the-spring-boot-starter-for-credentials-support), defines the class [SpringCredentialConfigurationProperties](https://github.com/swedenconnect/credentials-support/blob/main/spring/credentials-support-spring-boot-starter/src/main/java/se/swedenconnect/security/credential/spring/autoconfigure/SpringCredentialConfigurationProperties.html). This class is the main Spring Boot configuration properties (having the key `credential`) class for autowiring bundles, collections and monitoring.

| Property | Description | Type |
| :--- | :--- | :--- |
| `bundles` | Configuration properties for bundles of credentials and key stores. See [Section 5.3.6](#credential-bundles-configuration-properties) above | [CredentialBundlesConfigurationProperties](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/config/properties/CredentialBundlesConfigurationProperties.java) |
| `collection` | Configuration for setting up a [PkiCredentialCollection](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredentialCollection.java) bean. See [Section 5.3.7](#pki-credential-collection-configuration-properties) above. | [PkiCredentialCollectionConfigurationProperties](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/config/properties/PkiCredentialCollectionConfigurationProperties.java) |
| `monitoring.enabled` | Whether credential monitoring is enabled. If enabled, a [CredentialMonitorBean](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/monitoring/CredentialMonitorBean.java) is set up to monitor all credentials (that are configured for monitoring). | Boolean |
| `monitoring.test-interval` | The interval between tests of credentials. The default is 10 minutes. | [Duration](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/time/Duration.html) |
| `monitoring.health-endpoint-enabled` | Whether a HealthEndpoint for monitoring should be set up. See [Section 8.3.1, Credential Monitoring Health Endpoint](#credential-monitoring-health-endpoint). | Boolean |

<a name="monitoring"></a>
## 6. Monitoring

When using a HSM there is a possibility that the connection with the device is lost. The result is that the instantiated credential stops working. Therefore the **credentials-support** library offers ways to test and reload credentials. The credential types that support testing and reloading implements the [ReloadablePkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/ReloadablePkiCredential.java) interface.

An application that makes use of credentials that may fail, and may need to be reloaded, needs to set up a monitor that periodically tests that all monitored credentials are functional, and if not, tries to reload them.

By implementing the [CredentialMonitorBean](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/monitoring/CredentialMonitorBean.java) interface and schedule it to run periodically, one or more credentials can be monitored.

The [DefaultCredentialMonitorBean](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/monitoring/DefaultCredentialMonitorBean.java) is the default implementation of this interface. It can be configured with a number of callbacks that can be used for raising alarms or produce audit logs.

Note: When using HSM:s and setting requirements on the keys, it is essential that the usage for the credential is reflected in the configuration. Otherwise, the default test function may try to perform a signature for key that only supports encryption/decryption.

> The [The Spring Boot Starter for Credentials Support](#the-spring-boot-starter-for-credentials-support) creates a monitor bean automatically based on the credential configuration.

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

By including the **credentials-support-spring** artifact, the Credential Support is extended with Spring features.

<a name="spring-factories"></a>
### 8.1. Spring Factories

The **credentials-support-spring**, offers the [se.swedenconnect.security.credential.spring.factory.PkiCredentialFactoryBean](https://github.com/swedenconnect/credentials-support/blob/main/spring/credentials-support-spring/src/main/java/se/swedenconnect/security/credential/spring/factory/PkiCredentialFactoryBean.java). This is a Spring-style factory that accepts different credential configuration objects (see [5.3](#configuration-support)).

> The [se.swedenconnect.security.credential.factory.PkiCredentialFactoryBean](https://github.com/swedenconnect/credentials-support/blob/main/spring/credentials-support-spring/src/main/java/se/swedenconnect/security/credential/factory/PkiCredentialFactoryBean.java) previously used in earlier versions of the **credentials-support** library has been deprecated and will be removed in future versions.

The library also offers the following factory beans:

- [KeyStoreFactoryBean](https://github.com/swedenconnect/credentials-support/blob/main/spring/credentials-support-spring/src/main/java/se/swedenconnect/security/credential/spring/factory/KeyStoreFactoryBean.java) - for creating [KeyStore](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/KeyStore.html) instances using the Spring factory bean concept. However, it is recommended to use the [Bundles Concept(#the-bundles-concept) when creating key stores.

- [X509CertificateFactoryBean](https://github.com/swedenconnect/credentials-support/blob/feature/main/spring/credentials-support-spring/src/main/java/se/swedenconnect/security/credential/spring/factory/X509CertificateFactoryBean.java) - for creating [X509Certificate](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/cert/X509Certificate.html) instances given a [Resource](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/core/io/Resource.html).

<a name="spring-converters"></a>
### 8.2. Spring Converters

A Spring [Converter](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/core/convert/converter/Converter.html) is an interface for type conversion. This feature is typically useful when using an application properties or YAML-file and we want to convert from Strings in the property file to certain types. 

The following converters are available:

- [PropertyToPrivateKeyConverter](https://github.com/swedenconnect/credentials-support/blob/main/spring/credentials-support-spring/src/main/java/se/swedenconnect/security/credential/spring/converters/PropertyToPrivateKeyConverter.java) - A [Converter](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/core/convert/converter/Converter.html) that gets a property value (e.g., `classpath:signing.key`) and instantiates a `PrivateKey` object.<br /><br /> Note: The converter only handles non-encrypted private keys in DER, PEM, and PKCS#8 formats.

- [PropertyToPublicKeyConverter](https://github.com/swedenconnect/credentials-support/blob/main/spring/credentials-support-spring/src/main/java/se/swedenconnect/security/credential/spring/converters/PropertyToPublicKeyConverter.java) - A [Converter](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/core/convert/converter/Converter.html) that gets a property value (e.g., `classpath:trust.key`) and instantiates a `PublicKey` object.

- [PropertyToX509CertificateConverter](https://github.com/swedenconnect/credentials-support/blob/main/spring/credentials-support-spring/src/main/java/se/swedenconnect/security/credential/spring/converters/PropertyToX509CertificateConverter.java) - A [Converter](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/core/convert/converter/Converter.html) that gets a property value (e.g., `classpath:cert.crt`) and instantiates an `X509Certificate` object. The converter also handles "inlined" PEM certificates.

- [PkiCredentialReferenceConverter](https://github.com/swedenconnect/credentials-support/blob/main/spring/credentials-support-spring/src/main/java/se/swedenconnect/security/credential/spring/converters/PkiCredentialReferenceConverter.java) - A [Converter](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/core/convert/converter/Converter.html) that accepts a string that is a reference to a registered [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) and uses the
system [CredentialBundles](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/bundle/CredentialBundles.java) bean to create a resolvable [PkiCredentialReference](https://github.com/swedenconnect/credentials-support/blob/main/spring/credentials-support-spring/src/main/java/se/swedenconnect/security/credential/spring/config/PkiCredentialReference.java).

- [KeyStoreReferenceConverter](https://github.com/swedenconnect/credentials-support/blob/main/spring/credentials-support-spring/src/main/java/se/swedenconnect/security/credential/spring/converters/KeyStoreReferenceConverter.java) - A [Converter](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/core/convert/converter/Converter.html) that accepts a string that is a reference to a registered [KeyStore](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/KeyStore.html) and uses the system [CredentialBundles](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/bundle/CredentialBundles.java) bean to create a resolvable [KeyStoreReference](https://github.com/swedenconnect/credentials-support/blob/main/spring/credentials-support-spring/src/main/java/se/swedenconnect/security/credential/spring/config/KeyStoreReference.java).

If the Spring Boot starter is used, these converters will be automatically installed. Otherwise, they have to be "manually" configured, see <https://docs.spring.io/spring-framework/reference/core/validation/convert.html>.


<a name="the-spring-boot-starter-for-credentials-support"></a>
### 8.3. The Spring Boot Starter for Credentials Support

The **credentials-support-spring-boot-starter** gives a number of useful features:

- Injection of a fully populated [CredentialBundles](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/bundle/CredentialBundles.java) bean. This bean is populated based on the configuration described in [Section 5, Credential Bundles, Collections and Configuration Support](#credential-bundles-collections-and-configuration-support).

- Automatic registration of the converters documented in [Section 8.2, Spring Converters](#spring-converters).

- The creation and injection of a scheduled [CredentialMonitorBean](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/monitoring/CredentialMonitorBean.java) bean.

- As part of the monitoring of credentials a number of application events are published. These events may be used for alarms or audit logging. The events are:

    - [SuccessfulCredentialTestEvent](https://github.com/swedenconnect/credentials-support/blob/main/spring/credentials-support-spring-boot-starter/src/main/java/se/swedenconnect/security/credential/spring/monitoring/events/SuccessfulCredentialTestEvent.java) - An event that is signalled when a credential has been tested and the test was successful.
    
    - [FailedCredentialTestEvent](https://github.com/swedenconnect/credentials-support/blob/main/spring/credentials-support-spring-boot-starter/src/main/java/se/swedenconnect/security/credential/spring/monitoring/events/FailedCredentialTestEvent.java) - An event that is signalled when a credential has been tested and the test failed.
    
    - [SuccessfulCredentialReloadEvent](https://github.com/swedenconnect/credentials-support/blob/main/spring/credentials-support-spring-boot-starter/src/main/java/se/swedenconnect/security/credential/spring/monitoring/events/SuccessfulCredentialReloadEvent.java) - An event that is signalled when a credential has been reloaded successfully.
    
    - [FailedCredentialReloadEvent](https://github.com/swedenconnect/credentials-support/blob/main/spring/credentials-support-spring-boot-starter/src/main/java/se/swedenconnect/security/credential/spring/monitoring/events/FailedCredentialReloadEvent.java) - An event that is signalled when a credential has been reloaded with an error. This means that the credential no longer is functional.
    
- If configured (`credential.bundle.monitoring.health-endpoint-enabled` is set), an actuator health endpoint for credential monitoring is configured and made active. See below.

<a name="credential-monitoring-health-endpoint"></a>
#### 8.3.1. Credential Monitoring Health Endpoint

If the property `credential.bundle.monitoring.health-endpoint-enabled` is set, the actuator health endpoint [CredentialMonitorHealthIndicator](https://github.com/swedenconnect/credentials-support/blob/main/spring/credentials-support-spring-boot-starter/src/main/java/se/swedenconnect/security/credential/spring/actuator/CredentialMonitorHealthIndicator.java) is created and registered under the name `credential-monitor`.

If everything is looking good (no failed tests of reloads), an output like the following will be returned:

```json
{
  "status" : "UP",
  "details" : {
    "credentials" : [ 
      {
        "credential-name" : "Signing",
        "test-result" : "success"
      }, 
      {
         "credential-name" : "Encryption",
        "test-result" : "success"
      }
    ]
  }
}
```

The `credential-name` holds the configured name for the credential (see [Section 3.1](#credential-name)).

An error may look like:

```json
{
  "status" : "DOWN",
  "details" : {
    "credentials" : [ 
      {
        "credential-name" : "Signing",
        "test-result" : "success"
      }, 
      {
        "credential-name" : "Encryption",
        "test-result" : "failure",
        "test-error" : "Failed to access the private key",
        "test-exception" : "java.lang.SecurityException",
        "reload-result" : "failure",
        "reload-error" : "No contact with PKCS#11 device",
        "reload-exception" : "java.security.KeyStoreException"
      }
    ]
  }
}
```

In the above example it seems like both testing and reloading of the credential named "Encryption" has failed. 

The health endpoint delivers a details-map, where the `credentials` key holds a list of objects (one for each monitored credential). These objects have the following fields:

| Field | Description |
| :--- | :--- |
| `credential-name` | The name of the credential that was tested (and possible reloaded). |
| `test-result` | The result of a test. May be `success` or `failure`. |
| `test-error` | If the `test-result` is `failure`, this field holds a string describing the test error. |
| `test-exception` | If the `test-result` is `failure`, this field holds the class name for the exception that occurred during testing. |
| `reload-result` | If a test failed, the credential is reloaded. This field holds the result of the reloading. May be `success` or `failure`. |
| `reload-error` | If the `reload-result` is `failure`, this field holds a string describing the reload error. |
| `reload-exception` | If the `reload-result` is `failure`, this field holds the class name for the exception that occurred during reloading. |

<a name="opensaml-support"></a>
## 9. OpenSAML Support

The library **credentials-support-opensaml** contains the [OpenSamlCredential](https://github.com/swedenconnect/credentials-support/blob/main/opensaml/src/main/java/se/swedenconnect/security/credential/opensaml/OpenSamlCredential.java) class which is a class that wraps a [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) as an OpenSAML [X509Credential](https://shibboleth.net/api/java-opensaml/5.0.0/org/opensaml/security/x509/X509Credential.html). This enables us to use the configuration support of the **credentials-support** library and use our credentials in an OpenSAML context.

The **credentials-support-opensaml** library also defines the following transformers:

- [OpenSamlCredentialTransformerFunction](https://github.com/swedenconnect/credentials-support/blob/main/opensaml/src/main/java/se/swedenconnect/security/credential/opensaml/OpenSamlCredentialTransformerFunction.java), which can be supplied to the `transform` method of an existing [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) and create an [OpenSamlCredential](https://github.com/swedenconnect/credentials-support/blob/main/opensaml/src/main/java/se/swedenconnect/security/credential/opensaml/OpenSamlCredential.java) instance.

- [KeyDescriptorTransformerFunction](https://github.com/swedenconnect/credentials-support/blob/main/opensaml/src/main/java/se/swedenconnect/security/credential/opensaml/KeyDescriptorTransformerFunction.java), which can be used to create a SAML `md:KeyDescriptor` element to be included in SAML metadata.

<a name="nimbus-support"></a>
## 10. Nimbus Support

The **credentials-support-nimbus** library offers support for working with [Nimbus](https://connect2id.com/products/nimbus-jose-jwt) datatypes such as the [JWK](https://connect2id.com/products/nimbus-jose-jwt/examples/jwk-generation) class in conjunction with [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) objects.

It introduces the [JwkTransformerFunction](https://github.com/swedenconnect/credentials-support/blob/main/nimbus/src/main/java/se/swedenconnect/security/credential/nimbus/JwkTransformerFunction.java) for transforming a [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) into a [JWK](https://www.javadoc.io/doc/com.nimbusds/nimbus-jose-jwt/latest/com/nimbusds/jose/jwk/JWK.html) instance.

Also check the [JwkMetadataProperties](https://github.com/swedenconnect/credentials-support/blob/main/nimbus/src/main/java/se/swedenconnect/security/credential/nimbus/JwkMetadataProperties.java) for definitions of metadata keys useful for an JWK.

> Note: This library will be extended with more useful features in future versions.

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

Copyright &copy; 2020-2026, [Sweden Connect](https://swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
