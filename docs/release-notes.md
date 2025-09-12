![Logo](https://docs.swedenconnect.se/technical-framework/img/sweden-connect.png)

# credentials-support

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.security/credentials-support/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.security/credentials-support)

---

## Release Notes

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
