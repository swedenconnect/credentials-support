![Logo](https://github.com/swedenconnect/technical-framework/blob/master/img/sweden-connect.png)

# credentials-support - Main Features

---

## Table of contents

1. [**Credential Types**](#credential-types)
    
    1.1. [BasicCredential](#basiccredential)
    
    1.2. [KeyStoreCredential](#keystorecredential)
    
2. [**PkiCredential Features**](#pkicredential-features)

    2.1. [Credential Name](#credential-name)
    
    2.2. [Transformation to other Formats](#transformation-to-other-formats)
    
    2.3. [Monitoring](#monitoring)
    
    2.4. [Credential Metadata](#credential-metadata)
    
3. [**Builders and Factories**](#factories)

    3.1. [KeyStore Builder and Factory](#keystore-builder-and-factory)
    
    3.2. [Credential Factory](#credential-factory)
    


4. [**Credential Bundles and Configuration Support**](#credential-bundles-and-configuration-support)

    4.1. [The Bundles Concept](#the-bundles-concept)
    
    4.2. [Configuration Support](#configuration-support)
    
    4.2.1. [Basic Configuration Concepts](#basic-configuration-concepts)    
    
    4.2.2. [Key Store Configurations](#key-store-configurations)
    
    
---

<a name="credential-types"></a>
## 1. Credential Types

The **credentials-support** library defines three classes implementing the [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) interface and a wrapper that takes a [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) into an OpenSAML credential type.

<a name="basiccredential"></a>
### 1.1. BasicCredential

The [BasicCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/BasicCredential.java) class is a simple implementation of the [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) interface that is created by providing the private key and certificate (or just a public key). This class can for example be used when you have the key and certificate stored on file.

<a name="keystorecredential"></a>
### 1.2. KeyStoreCredential

The [KeyStoreCredential](https://github.com/swedenconnect/credentials-support/blob/main/credentials-support/src/main/java/se/swedenconnect/security/credential/KeyStoreCredential.java) class is backed by a KeyStore and is initialized by providing a loaded KeyStore instance (see [Factories](#factories) below) and giving the entry alias and key password. 






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

---

Copyright &copy; 2020-2024, [Sweden Connect](https://swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
