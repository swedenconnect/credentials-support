![Logo](https://github.com/swedenconnect/technical-framework/blob/master/img/sweden-connect.png)

# credentials-support

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.security/credentials-support/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.security/credentials-support)

Java library for PKI credentials support, including PKCS#11 and HSM:s.

---

## Table of contents

1. [**Overview**](#overview)

2. [**Credential types**](#credential-types)

    2.1. [BasicCredential](#basiccredential)
  
    2.2. [KeyStoreCredential](#keystorecredential)
  
    2.3. [Pkcs11Credential](#pkcs11credential)
  
    2.4. [OpenSamlCredential](#opensamlcredential)

3. [**Spring Framework**](#spring-framework)

    3.1. [Credentials as beans](#credentials-as-beans)
  
    3.2. [Converters](#converters)
  
    3.3. [Factories](#factories)
  
    3.3.1. [For Shibboleth users](#for-shibboleth-users)
  
4. [**Monitoring and reloading credentials**](#monitoring-and-reloading-credentials)

5. [**Using SoftHSM to test PKCS#11 credentials**](#using-softhsm-to-test-pkcs11-credentials)

6. [**API documentation**](#api-documentation)

---

<a name="overview"></a>
## 1. Overview

The **credentials-support** library defines an uniform way of representing PKI credentials (private keys and X.509 certificates) by introducing the [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) interface.

The library supports both basic credentials stored on file, or in a key store (JKS, PKCS#12), as well as PKCS#11 credentials residing on a Hardware Security Module.

<a name="credential-types"></a>
## 2. Credential types

The library defines three classes implementing the [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) interface and a wrapper that takes a [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) into an OpenSAML credential type.

<a name="basiccredential"></a>
### 2.1. BasicCredential

The [BasicCredential](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/BasicCredential.java) class is a simple implementation of the [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) interface that is created by providing the private key and certificate. This class can for example be used when you have the key and certificate stored on file.

<a name="keystorecredential"></a>
### 2.2. KeyStoreCredential

The [KeyStoreCredential](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/KeyStoreCredential.java) class is backed by a KeyStore and can be initialized in a number of ways:

* By loading a KeyStore from a Spring Resource and then getting the certificate and private key by providing the keystore alias and password.

* By providing an already loaded KeyStore instance (see [Factories](#factories) below) and giving the entry alias and key password. 

This class also supports handling of PKCS#11 credentials. This requires using a security provider that supports creating a KeyStore based on an underlying PKCS#11 implementation (for example the SunPKCS11 provider). There are three ways of creating a KeyStoreCredential for use with PKCS#11:

 * **Supplying an already existing PKCS#11 KeyStore** - In some cases you may already have loaded a KeyStore using a security provider configured for PKCS#11. In
these cases the initialization of the KeyStoreCredential is identical with option number 2 above. You simply create your KeyStoreCredential instance by giving the KeyStore instance, the entry alias and key password.

 * **Supplying the provider name of a Security provider configured for your PKCS#11 device** - Another possibility is to supply the provider name of a security provider configured for PKCS#11. This could typically look something like:
 
```
// Create a SunPKCS11 provider instance using our PKCS#11 configuration ...
Provider provider = Security.getProvider("SunPKCS11");
provider = provider.configure(pkcs11CfgFile);
Security.addProvider(provider);
 
// Create a credential ...
KeyStoreCredential credential = new KeyStoreCredential(
    null, "PKCS11", provider.getName(), tokenPw, alias, null);
credential.init();
```

* **Supplying the PKCS#11 configuration file** - In the above example we created the SunPKCS11 provider instance manually. It is also to create a KeyStoreCredential instance by supplying the PKCS#11 configuration file.

```
KeyStoreCredential credential = new KeyStoreCredential(
    null, "PKCS11", "SunPKCS11", tokenPw, alias, null);
credential.setPkcs11Configuration(pkcs11CfgFile);
credential.init();
```

**Note:** As an alternative of using KeyStoreCredential for PKCS#11 credentials see the [Pkcs11Credential](#pkcs11credential) class below.

<a name="pkcs11credential"></a>
### 2.3. Pkcs11Credential

As was described above, the KeyStoreCredential can be used for PKCS#11 credentials, but it is limited to those Java security providers that also offers a KeyStore abstraction of the PKCS#11 device entry. The [Pkcs11Credential](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/Pkcs11Credential.java) is a class that does not make any assumptions on how the security provider in use handles its PKCS#11 entries. Instead it uses the [Pkcs11Configuration](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/pkcs11conf/Pkcs11Configuration.java) interface.

The [Pkcs11Configuration](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/pkcs11conf/Pkcs11Configuration.java) interface declares the methods:

- `getProvider()` - Returns the Java Security Provider that should be used for the PKCS#11 credential.

- `getPrivateKeyProvider()` - Returns a provider function that returns the private key of the credential.

- `getCredentialProvider()` - Returns a provider function that returns the private key **and** certificate of the credential.

The default implementation of this interface is [DefaultPkcs11Configuration](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/pkcs11conf/DefaultPkcs11Configuration.java). This implementation uses the SunPKCS11 security provider. This class can be used in two ways:

* **By providing a PKCS#11 configuration file** - In these cases a call to `getProvider()` will use the SunPKCS11 provider and create a new provider named SunPKCS11-<name>, where name is the name given in the PKCS#11 configuration file.

* **By using a statically configured SunPKCS11 provider** - The SunPKCS11 provider can also be configured in the `java.security` file (see below). In these cases the [DefaultPkcs11Configuration](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/pkcs11conf/DefaultPkcs11Configuration.java) should not be configured with any arguments.

*Example of a statically configured SunPKCS11 provider:*

```
...
security.provider.13=SunPKCS11 /opt/bar/cfg/pkcs11.cfg
...
```

For more information, see the [Oracle PKCS#11 Reference Guide](https://docs.oracle.com/en/java/javase/14/security/pkcs11-reference-guide1.html).

**Note:** If you are using another PKCS#11 security provider than SunPKCS11 you will have to provide your own implementation of [DefaultPkcs11Configuration](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/pkcs11conf/DefaultPkcs11Configuration.java). In these cases the abstract base class [AbstractPkcs11Configuration](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/pkcs11conf/AbstractPkcs11Configuration.java) may be useful.

OK, so what about the [Pkcs11Credential](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/Pkcs11Credential.java) class? Well, once the configuration is in place it's really simple. You create an instance of the class be providing the alias (PKCS#11 label) and PIN (the password) along with the configuration discussed above.

<a name="opensamlcredential"></a>
### 2.4. OpenSamlCredential

OpenSAML offers an interface, `X509Credential`, similar to the [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) interface. In order to use any of the types described above together with OpenSAML the **credentials-support** library offers the [OpenSamlCredential](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/opensaml/OpenSamlCredential.java) class. This class simply wraps a class implementing the [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) interface so that it also implements the OpenSAML `X509Credential` interface. In this way you can make use of the benefits of the **credentials-support** library such as PKCS#11 support and monitoring of credentials in an OpenSAML environment.


**Note:** OpenSAML 4 is an optional dependency to the **credentials-support** meaning that if you want to use the [OpenSamlCredential](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/opensaml/OpenSamlCredential.java) you need to explicitly include the dependency `org.opensaml:opensaml-security-api`.


<a name="spring-framework"></a>
## 3. Spring Framework

The library uses Spring Framework, and especially the `InitializingBean` and `DisposableBean` interfaces. 

If you are not using the library in a Spring environment you will make sure that you invoke the `afterPropertiesSet()` method directly after a bean has been created and all its properties assigned.

<a name="credentials-as-beans"></a>
### 3.1. Credentials as beans

The [SpringBootTest](https://github.com/swedenconnect/credentials-support/blob/main/src/test/java/se/swedenconnect/security/credential/spring/SpringBootTest.java) along with its configuration class [CredentialsConfiguration](https://github.com/swedenconnect/credentials-support/blob/main/src/test/java/se/swedenconnect/security/credential/spring/CredentialsConfiguration.java) gives some examples of how credentials can be instantiated as Spring beans. It also illustrates how monitoring can be set up (see [Monitoring and reloading credentials](#monitoring-and-reloading-credentials) below.

If you are using old-fashioned Spring with XML-configuration files, take a look at [SpringTest](https://github.com/swedenconnect/credentials-support/blob/main/src/test/java/se/swedenconnect/security/credential/spring/SpringTest.java) and its configuration file [test-config.xml](https://github.com/swedenconnect/credentials-support/blob/main/src/test/resources/test-config.xml).

<a name="converters"></a>
### 3.2. Converters

The **credentials-support** library defines two classes; [PropertyToPrivateKeyConverter](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/converters/PropertyToPrivateKeyConverter.java) and [PropertyToX509CertificateConverter](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/converters/PropertyToX509CertificateConverter.java). These are handy when you want a simple way from a property in an application properties file to a ready to go object (`PrivateKey` or `X509Certificate`).

Check out the tests in [PropertyToPrivateKeyConverterTest](https://github.com/swedenconnect/credentials-support/blob/main/src/test/java/se/swedenconnect/security/credential/converters/PropertyToPrivateKeyConverterTest.java) and [PropertyToX509CertificateConverterTest](https://github.com/swedenconnect/credentials-support/blob/main/src/test/java/se/swedenconnect/security/credential/converters/PropertyToX509CertificateConverterTest.java) for how to register the converters and make use of them.

<a name="factories"></a>
### 3.3. Factories

When using Spring making use of factory beans are often useful. The **credentials-support** library defines the [KeyStoreFactoryBean](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/factory/KeyStoreFactoryBean.java) for an easy way to create a `KeyStore` object and the [X509CertificateFactoryBean](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/factory/X509CertificateFactoryBean.java) for creating `X509Certificate` objects given a Spring `Resource`.

<a name="for-shibboleth-users"></a>
#### 3.3.1. For Shibboleth users

The Shibboleth library `net.shibboleth.ext:spring-extensions` defines a number of useful Spring factory bean classes in the `net.shibboleth.ext.spring.factory` package. These can of course be 
used instead of the classes defined in the **credentials-support** library, but let's go through 
them and give some information that is useful to know about:

**KeyStoreFactoryBean**

Basically the same as [se.swedenconnect.security.credential.factory.KeyStoreFactoryBean](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/factory/KeyStoreFactoryBean.java). The only difference is that the Shibboleth implementations doesn't let you create a PKCS#11 KeyStore instance. 

> This is probably an oversight from the Shib-team. The `resource` property is checked so that it is non-null, but in the case when loading a PKCS#11 KeyStore you don't need an input stream but supply `null`.

**PKCS11PrivateKeyFactoryBean**

A factory bean that creates a `PrivateKey` instance that resides on a token that is accesses via PKCS#11.

This class can only be used if you are fine with using Sun's PKCS#11 security provider. If your device requires another security provider this class isn'f for you.

Also, by using the credentials support in **credentials-support** you also have the possibility to monitor, and possibly reload, PKCS#11 credentials. This is not possible if you are using the Shibboleth `PKCS11PrivateKeyFactoryBean`.

**X509CertificateFactoryBean**

Basically identical to [se.swedenconnect.security.credential.factory.X509CertificateFactoryBean](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/factory/X509CertificateFactoryBean.java). 

So, the `X509CertificateFactoryBean` of the **credentials-support** library is really indented for those that don't use Shibboleth.

<a name="monitoring-and-reloading-credentials"></a>
## 4. Monitoring and reloading credentials

When using a HSM there is a possibility that the connection with the device is lost. The result is that the instantiated credential stops working. Therefore the **credentials-support** library offers ways to test and reload credentials. The credential types that support testing and reloading implements the [ReloadablePkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/ReloadablePkiCredential.java) interface.

An application that makes use of credentials that may fail, and may need to be reloaded, needs to set up a monitor that periodically tests that all monitored credentials are functional, and if not, tries to reload them.

By implementing the [CredentialMonitorBean](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/monitoring/CredentialMonitorBean.java) interface and schedule it to run periodically, one or more credentials can be monitored.

The [DefaultCredentialMonitorBean](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/monitoring/DefaultCredentialMonitorBean.java) is the default implementation of this interface. It can be configured with a number of callbacks that can be used for raising alarms or produce audit logs.

See [SpringBootTest](https://github.com/swedenconnect/credentials-support/blob/main/src/test/java/se/swedenconnect/security/credential/spring/SpringBootTest.java) and [CredentialsConfiguration](https://github.com/swedenconnect/credentials-support/blob/main/src/test/java/se/swedenconnect/security/credential/spring/CredentialsConfiguration.java) for an example of how to set up a scheduled monitor in Spring Boot.

<a name="using-softhsm-to-test-pkcs11-credentials"></a>
## 5. Using SoftHSM to test PKCS#11 credentials

[SoftHSM](https://wiki.opendnssec.org/display/SoftHSMDOCS) is a great way to test your PKCS#11 credentials without an actual HSM. The **credentials-support** library contains a simple Spring Boot app that illustrates how to set up SoftHSM and how to configure your PKCS#11 devices, see the [softhsm](https://github.com/swedenconnect/credentials-support/tree/main/softhsm) directory for details.

<a name="api-documentation"></a>
## 6. API documentation

* [Java API documentation](https://docs.swedenconnect.se/credentials-support/apidoc/)

---

Copyright &copy; 2020-2021, [Sweden Connect](https://swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
