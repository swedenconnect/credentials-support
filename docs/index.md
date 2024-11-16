![Logo](https://github.com/swedenconnect/technical-framework/blob/master/img/sweden-connect.png)

# credentials-support

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.security/credentials-support/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.security/credentials-support)

Java libraries for PKI credentials support, including PKCS#11 and HSM:s.

---

The **credentials-support** library defines an uniform way of representing PKI credentials (private keys and X.509 certificates) by introducing the [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) interface.

The library supports both basic credentials stored on file, or in a key store (JKS, PKCS#12), as well as PKCS#11 credentials residing on a Hardware Security Module.

The **credentials-support-opensaml** library offers an add-on for OpenSAML, where a [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) object can be used to create an OpenSAML credential.

The **credentials-support-spring** library offers Spring add-ons consisting of converters, factories and configuration support.

The **credentials-support-spring-boot-starter** library is a Spring Boot starter that can be used for an easy and straight forward way of configuring credentials that are to be used in a Spring Boot application.

**Contents:**

- [Maven](maven.html) - How to access the credentials-support libraries from Maven central.

- [Credential types](credential-types.html) - The different [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) implementations.

---

Copyright &copy; 2020-2024, [Sweden Connect](https://swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).