![Logo](https://docs.swedenconnect.se/technical-framework/img/sweden-connect.png)

# credentials-support

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.security/credentials-support/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.security/credentials-support)

---

## Release Notes

### 2.1.1

**Date:**

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

Copyright &copy; 2020-2025, [Sweden Connect](https://swedenconnect.se). Licensed under version 2.0 of
the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
