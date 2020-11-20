![Logo](https://github.com/swedenconnect/technical-framework/blob/master/img/sweden-connect.png)

# credentials-support

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Java library for PKI credentials support, including PKCS#11 and HSM:s.

---

TODO

### For Shibboleth Users

The Shibboleth library `net.shibboleth.ext:spring-extensions` defines a number of useful Spring factory bean classes in the `net.shibboleth.ext.spring.factory` package. These can of course be 
used instead of the classes defined in the **credentials-support** library, but let's go through 
them and give some information that is useful to know about:

##### KeyStoreFactoryBean

Basically the same as [se.swedenconnect.security.credential.spring.KeyStoreFactoryBean](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/spring/KeyStoreFactoryBean.java). The only difference is that the Shibboleth implementations doesn't let you create a PKCS#11 KeyStore instance. 

> This is probably an oversight from the Shib-team. The `resource` property is checked so that it is non-null, but in the case when loading a PKCS#11 KeyStore you don't need an input stream but supply `null`.

##### PKCS11PrivateKeyFactoryBean

A factory bean that creates a `PrivateKey` instance that resides on a token that is accesses via PKCS#11.

This class can only be used if you are fine with using Sun's PKCS#11 security provider. If your
device requires another security provider this class isn'f for you.

Also, by using the credentials support in **credentials-support** you also have the possibility to monitor, and possibly re-load, PKCS#11 credentials. This is not possible if you are using the Shibboleth `PKCS11PrivateKeyFactoryBean`.

##### PrivateKeyFactoryBean

##### X509CertificateFactoryBean

Basically identical to [se.swedenconnect.security.credential.spring.X509CertificateFactoryBean](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/spring/X509CertificateFactoryBean). 

So, the `X509CertificateFactoryBean` of the **credentials-support** library is really indented for those that don't use Shibboleth.


---

Copyright &copy; 2020, [Sweden Connect](https://swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
