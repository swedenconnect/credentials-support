![Logo](https://docs.swedenconnect.se/technical-framework/img/sweden-connect.png)

# credentials-support

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.security/credentials-support/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.security/credentials-support)

---

## Release Notes

### 2.0.2

**Date:** -

- The `PropertyToPublicKeyConverter` was added to the Spring Boot Starter autoconfiguration.

- Fixed bug that occurred if the same PKCS#11 provider were used for several keys. See https://github.com/swedenconnect/credentials-support/issues/74.

### 2.0.1

**Date:** 2024-12-07

- Moved Spring application events from the Spring Boot Starter to the Spring library to make them re-usable by other libraries.

### 2.0.0

**Date:** 2024-12-06

- A completely new base with support for Spring Boot, OpenSAML, Nimbus.

---

Copyright &copy; 2020-2025, [Sweden Connect](https://swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).