![Logo](https://docs.swedenconnect.se/technical-framework/img/sweden-connect.png)

# credentials-support

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.security/credentials-support/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.security/credentials-support)

---

## Release Notes

### 2.3.0

**Date:** _not yet released_

- Lombok is no longer used.

- Removed deprecated code:
  - The `PkiCredentialFactoryBean` and `PkiCredentialConfigurationProperties` classes in the `se.swedenconnect.security.credential.factory` package. Use the classes in `se.swedenconnect.security.credential.spring.factory` and `se.swedenconnect.security.credential.config.properties`.
  - The `set...Function` methods of `JwkTransformerFunction` and `OpenSamlCredentialTransformerFunction`. Use the corresponding `with...Function` methods.
  - `JwkTransformerFunction.serializable()`. Created JWKs are always serializable.
  - The `credential.bundles.monitoring.*` properties. Use `credential.monitoring.*`.

- Fixed a thread-safety bug in [JwkTransformerFunction](https://github.com/swedenconnect/credentials-support/blob/main/nimbus/src/main/java/se/swedenconnect/security/credential/nimbus/JwkTransformerFunction.java). A single SHA-256 digest instance was shared between all threads, so JWKs created concurrently could get an incorrect `x5t#S256` thumbprint (or the call could fail).

- A missing classpath resource (for example a mistyped key store location) resulted in an empty key store, or a `NullPointerException` for PEM files, instead of an error. [DefaultConfigurationResourceLoader](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/config/DefaultConfigurationResourceLoader.java) now throws a `FileNotFoundException`.

- [KeyStoreFactory](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/factory/KeyStoreFactory.java) did not close the input stream after loading a key store from a configured location, which leaked a file handle (or HTTP connection) for each loaded key store.

- The credential cache of [PkiCredentialFactory](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/factory/PkiCredentialFactory.java) was keyed by the hash code of the configuration only, so two different configurations with the same hash code could return the wrong credential. The cache is now keyed by the configuration itself.

- [StoreConfigurationProperties](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/config/properties/StoreConfigurationProperties.java) lacked `equals` and `hashCode`, so identical key store configurations were never found in the credential cache, and a PKCS#11 key store could be loaded twice.

- After a reload of an HSM credential, other threads could keep using the old (no longer working) private key. The private key reference in [KeyStoreCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/KeyStoreCredential.java) and [Pkcs11Credential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/pkcs11/Pkcs11Credential.java) is now safely shared between threads.

- Loading certificates from a PKCS#11 device using [SunPkcs11CertificatesAccessor](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/pkcs11/SunPkcs11CertificatesAccessor.java) failed with a `NullPointerException` when the key entry had no certificate chain, and could return an array holding `null` when no certificate was found.

- A [KeyStoreCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/KeyStoreCredential.java) for a PKCS#11 key store could not be created without a key password, even though the password is documented as optional. Such a credential is now created without reload support.

- The PIN held by the reloader of a PKCS#11 [KeyStoreCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/KeyStoreCredential.java) was not cleared from memory when the credential was destroyed.

- The key store type `pkcs11` (lower case) was rejected by [KeyStoreFactory](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/factory/KeyStoreFactory.java) when no location was given, and not recognized by [KeyStoreFactoryBean](https://github.com/swedenconnect/credentials-support/blob/main/spring/credentials-support-spring/src/main/java/se/swedenconnect/security/credential/spring/factory/KeyStoreFactoryBean.java). The type is now case-insensitive everywhere.

- [AbstractKeyStorePkiCredentialContainer](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/container/AbstractKeyStorePkiCredentialContainer.java) forgot about a generated key before it had been removed from the key store. If the removal failed (for example due to a lost HSM connection), the key was left in the key store and never removed later. Also, a key was left in the key store if creating its credential failed.

- The expiry time of a key generated by [AbstractKeyStorePkiCredentialContainer](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/container/AbstractKeyStorePkiCredentialContainer.java) was read from the credential's current certificate. Assigning a new certificate with a longer validity therefore extended the lifetime of the key. The expiry time is now fixed when the key is generated.

- A certificate assigned to a credential from [InMemoryPkiCredentialContainer](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/container/InMemoryPkiCredentialContainer.java) was lost on the next call to `getCredential`.

- [EncryptionMethodMetadata](https://github.com/swedenconnect/credentials-support/blob/main/opensaml/src/main/java/se/swedenconnect/security/credential/opensaml/EncryptionMethodMetadata.java) did not trim the algorithm, so a space before `;` in an encryption method configuration ended up in the SAML metadata.

- [AbstractSunPkcs11Configuration](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/pkcs11/AbstractSunPkcs11Configuration.java) could configure and install the PKCS#11 provider twice if used from several threads at the same time.

### 2.2.1

**Date:** 2026-04-24

- Upgrade of dependencies.

### 2.2.0

**Date:** 2026-03-06

- Upgrade to Spring Boot 4, Spring 7. Also, Java 21 is now the minimum supported version.

### 2.1.2

**Date:** 2026-01-19

- Bug described by [IS-108](https://github.com/swedenconnect/credentials-support/issues/108), where
  key compatibility checked failed when using PKCS#11.

### 2.1.1

**Date:** 2025-12-18

- Access to the private key for `KeyStoreCredential` objects were synchornized,
  which led to long waits when many threads tried to access the same key. This has
  been changed and no synchronization is needed anymore.
  See <https://github.com/swedenconnect/credentials-support/issues/102>.

- The `DefaultCredentialTestFunction` was updated to test decryption for
  credentials that are marked as encryption/decryption credentials.
  See <https://github.com/swedenconnect/credentials-support/issues/101>.

- The log warning `credential.bundles.monitoring.* is assigned - use credential.monitoring.* instead` was issued even
  though no monitoring was configured. This has been fixed.
  See <https://github.com/swedenconnect/credentials-support/issues/98>.

- The `JwkTransformerFunction.serializable()` method has been deprecated, since the JWK will be serializable in all
  cases, i.e., no `KeyStore` is included in the JWK anymore.

- The customizer method `JwkTransformerFunction.publicJwk()` was introduces so that the `JwkTransformerFunction` can be
  used to create a JWK to be included in metadata.

### 2.1.0

**Date:** 2025-11-07

- Introduced
  the [PkiCredentialCollection](https://docs.swedenconnect.se/credentials-support/apidoc/se/swedenconnect/security/credential/PkiCredentialCollection.html)
  class that enables easier handling of several credentials.

-

Also, [PkiCredentialCollectionConfiguration](https://docs.swedenconnect.se/credentials-support/apidoc/se/swedenconnect/security/credential/config/PkiCredentialCollectionConfiguration.html)
and [PkiCredentialCollectionConfigurationProperties](https://docs.swedenconnect.se/credentials-support/apidoc/se/swedenconnect/security/credential/config/properties/PkiCredentialCollectionConfigurationProperties.html)
were added for configuration of
a [PkiCredentialCollection](https://docs.swedenconnect.se/credentials-support/apidoc/se/swedenconnect/security/credential/PkiCredentialCollection.html).
Also, the method `createCredentialCollection` was added
to [PkiCredentialFactory](https://docs.swedenconnect.se/credentials-support/apidoc/se/swedenconnect/security/credential/factory/PkiCredentialFactory.html).

- Using Spring Boot configuration,
  a [PkiCredentialCollection](https://docs.swedenconnect.se/credentials-support/apidoc/se/swedenconnect/security/credential/PkiCredentialCollection.html)
  bean can now be automatically created by providing configuration under the `credential.collection.*` property.

-

The [PkiCredential.Metadata](https://docs.swedenconnect.se/credentials-support/apidoc/se/swedenconnect/security/credential/PkiCredential.Metadata.html)
class has been extended with additional credential metadata properties:

- `usage` - For assigning a credential usage, for example "signing" or "encryption".
- `active-to` and `active-from` - For enabling "future signing credentials" and "previous encryption credentials".

-

The [OpenSamlMetadataProperties](https://docs.swedenconnect.se/credentials-support/apidoc/se/swedenconnect/security/credential/opensaml/OpenSamlMetadataProperties.html)
class was extended with the `encryption-methods` property that enables assigning SAML metadata encryption methods to an
encryption credential.

- Introduced
  the [KeyDescriptorTransformerFunction](https://docs.swedenconnect.se/credentials-support/apidoc/se/swedenconnect/security/credential/opensaml/OpenSamlMetadataProperties.html)
  that may be used to create a SAML metadata `md:KeyDescriptor` element.

### 2.0.7

**Date:** 2025-09-12

- Dependency updates.

- Fixed bug where `StoreCredentialConfigurationProperties.KeyConfigurationProperties` did not implement `hashcode`
  and `equals`, making it impossible to cache.

- We no longer assume that Spring Boot Actuator is on the classpath.

### 2.0.6

**Date:** 2025-05-08

- Dependency updates only.

### 2.0.5

**Date:** 2025-03-26

- When transforming from the old way of configuring credentials to the new we are a bit forgiving to avoid unnecessary
  confusion.

### 2.0.4

**Date:** 2025-02-26

- Extended
  the [PkiCredentialFactory](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/factory/PkiCredentialFactory.java)
  class so that it can be instantiated as a bean for easier use. This bean is also automatically provided by the Spring
  Boot starter.

### 2.0.3

**Date:** 2025-02-10

- Functionality to create serializable JWKs using the `JwkTransformerFunction#serializable` function was added.

### 2.0.2

**Date:** 2025-01-21

- The `PropertyToPublicKeyConverter` was added to the Spring Boot Starter autoconfiguration.

- Fixed bug that occurred if the same PKCS#11 provider were used for several keys.
  See https://github.com/swedenconnect/credentials-support/issues/74.

### 2.0.1

**Date:** 2024-12-07

- Moved Spring application events from the Spring Boot Starter to the Spring library to make them re-usable by other
  libraries.

### 2.0.0

**Date:** 2024-12-06

- A completely new base with support for Spring Boot, OpenSAML, Nimbus.

---

Copyright &copy; 2020-2026, [Sweden Connect](https://swedenconnect.se). Licensed under version 2.0 of
the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
