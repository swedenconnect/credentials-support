/*
 * Copyright 2020-2023 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.swedenconnect.security.credential;

import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.core.io.Resource;
import org.springframework.util.Assert;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.credential.factory.KeyStoreFactoryBean;
import se.swedenconnect.security.credential.monitoring.DefaultCredentialTestFunction;

/**
 * A {@link KeyStore} backed implementation of the {@link PkiCredential} and {@link ReloadablePkiCredential} interfaces.
 * <p>
 * A {@code KeyStoreCredential} can be initialized in a number of ways:
 * </p>
 * <ol>
 * <li>By loading a {@link KeyStore} from a {@link Resource} and then getting the certificate and private key. This is
 * done either by using any of the constructors {@link #KeyStoreCredential(Resource, char[], String, char[])},
 * {@link #KeyStoreCredential(Resource, String, char[], String, char[])} or
 * {@link #KeyStoreCredential(Resource, String, String, char[], String, char[])} or by assigning all required properties
 * using setter-methods.</li>
 * <li>By providing an already loaded {@link KeyStore} instance and giving the entry alias and key password. This is
 * done either by using the constructor {@link #KeyStoreCredential(KeyStore, String, char[])} or by assigning all
 * required properties using setter-methods.</li>
 * </ol>
 * <p>
 * This class also supports handling of PKCS#11 credentials. This requires using a security provider that supports
 * creating a {@link KeyStore} based on an underlying PKCS#11 implementation (for example the SunPKCS11 provider). There
 * are three ways of creating a {@code KeyStoreCredential} for use with PKCS#11:
 * </p>
 * <p>
 * <b>Supplying an already existing PKCS#11 {@link KeyStore}</b> <br>
 * In some cases you may already have loaded a {@link KeyStore} using a security provider configured for PKCS#11. In
 * these cases the initialization of the {@code KeyStoreCredential} is identical with option number 2 above. You simply
 * create your {@code KeyStoreCredential} instance by giving the {@link KeyStore} instance, the entry alias and key
 * password either via the {@link #KeyStoreCredential(KeyStore, String, char[])} or by assigning all required properties
 * using setter-methods.
 * </p>
 * <p>
 * <b>Supplying the provider name of a Security provider configured for your PKCS#11 device</b> <br>
 * Another possibility is to supply the provider name of a security provider configured for PKCS#11. This could
 * typically look something like:
 * </p>
 *
 * <pre>
 * // Create a SunPKCS11 provider instance using our PKCS#11 configuration ...
 * Provider provider = Security.getProvider("SunPKCS11");
 * provider = provider.configure(pkcs11CfgFile);
 * Security.addProvider(provider);
 *
 * // Create a credential ...
 * KeyStoreCredential credential = new KeyStoreCredential(null, "PKCS11", provider.getName(), tokenPw, alias, null);
 * credential.init();
 * </pre>
 * <p>
 * <b>Supplying the PKCS#11 configuration file</b> <br>
 * In the above example we created the SunPKCS11 provider instance manually. It is also to create a
 * {@code KeyStoreCredential} instance by supplying the PKCS#11 configuration file.
 * </p>
 *
 * <pre>
 * KeyStoreCredential credential = new KeyStoreCredential(null, "PKCS11", "SunPKCS11", tokenPw, alias, null);
 * credential.setPkcs11Configuration(pkcs11CfgFile);
 * credential.init();
 * </pre>
 * <p>
 * <b>Note:</b> As an alternative of using {@code KeyStoreCredential} for PKCS#11 credentials see the
 * {@link Pkcs11Credential} class.
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class KeyStoreCredential extends AbstractReloadablePkiCredential {

  /** Factory for creating a KeyStore. */
  private KeyStoreFactoryBean keyStoreFactory = null;

  /** The password needed to unlock the KeyStore. */
  private char[] password;

  /** The keystore. */
  private KeyStore keyStore;

  /** The alias to the entry holding the key pair. */
  private String alias;

  /** the password to unlock the private key. */
  private char[] keyPassword;

  /** Whether the credential has been loaded? */
  private boolean loaded = false;

  /** Whether this is a hardware credential or not. */
  private boolean residesInHardware = false;

  /**
   * Default constructor.
   */
  public KeyStoreCredential() {
    super();
  }

  /**
   * Constructor accepting an already loaded {@link KeyStore}.
   *
   * @param keyStore the keystore to read the key pair from
   * @param alias the alias to the entry holding the key pair
   * @param keyPassword the password to unlock the key pair
   */
  public KeyStoreCredential(final KeyStore keyStore, final String alias, final char[] keyPassword) {
    this.setKeyStore(keyStore);
    this.setAlias(alias);
    this.setKeyPassword(keyPassword);
  }

  /**
   * A constructor that creates and loads a {@link KeyStore} from the given resource. The default KeyStore type is used
   * and the first security provider that can create such a KeyStore is used.
   *
   * @param resource the resource to load the {@link KeyStore} from
   * @param password the password needed to load the KeyStore
   * @param alias the entry alias for the certificate and private key
   * @param keyPassword the password needed to unlock the certificate and private key (if null, the same value as given
   *          for password is used)
   */
  public KeyStoreCredential(final Resource resource, final char[] password, final String alias,
      final char[] keyPassword) {
    this(resource, KeyStore.getDefaultType(), null, password, alias, keyPassword);
  }

  /**
   * A constructor that creates and loads a {@link KeyStore} of the given type from the given resource. The first
   * security provider that can create such a KeyStore is used.
   *
   * @param resource the resource to load the {@link KeyStore} from
   * @param type the KeyStore type
   * @param password the password needed to load the KeyStore
   * @param alias the entry alias for the certificate and private key
   * @param keyPassword the password needed to unlock the certificate and private key (if null, the same value as given
   *          for password is used)
   */
  public KeyStoreCredential(final Resource resource, final String type,
      final char[] password, final String alias, final char[] keyPassword) {
    this(resource, type, null, password, alias, keyPassword);
  }

  /**
   * A constructor that creates and loads a {@link KeyStore} of the given type from the given resource using the given
   * provider.
   *
   * @param resource the resource to load the {@link KeyStore} from
   * @param type the KeyStore type
   * @param provider the security provider to use when creating the KeyStore
   * @param password the password needed to load the KeyStore
   * @param alias the entry alias for the certificate and private key
   * @param keyPassword the password needed to unlock the certificate and private key (if null, the same value as given
   *          for password is used)
   */
  public KeyStoreCredential(final Resource resource, final String type, final String provider,
      final char[] password, final String alias, final char[] keyPassword) {

    this.setResource(resource);
    this.setType(type);
    this.setProvider(provider);
    this.setPassword(password);
    this.setAlias(alias);
    this.setKeyPassword(keyPassword);
  }

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() throws Exception {
    this.load();
  }

  /** {@inheritDoc} */
  @Override
  public void destroy() {
    if (this.password != null) {
      Arrays.fill(this.password, (char) 0);
    }
    if (this.keyPassword != null) {
      Arrays.fill(this.keyPassword, (char) 0);
    }
  }

  /** {@inheritDoc} */
  @Override
  public boolean isHardwareCredential() {
    return this.residesInHardware;
  }

  /**
   * Loads the KeyStore (if needed) and loads the private key and certificate.
   *
   * @throws Exception for errors loading the credential
   */
  private synchronized void load() throws Exception {
    if (this.loaded) {
      return;
    }

    // Set the 'loaded' flag before we load. If the loading fails we don't want to keep loading and loading ...
    //
    this.loaded = true;

    if (this.keyStore == null) {
      // The keystore has not been assigned, load it ...
      //
      if (this.keyStoreFactory == null) {
        throw new IllegalArgumentException("Missing parameters for creating KeyStore");
      }
      this.keyStoreFactory.afterPropertiesSet();
      this.keyStore = this.keyStoreFactory.getObject();

      // For PKCS11, install a default test function (if none has been set) ...
      //
      if ("PKCS11".equals(this.keyStore.getType()) && this.getTestFunction() == null) {
        final DefaultCredentialTestFunction testFunction = new DefaultCredentialTestFunction();
        testFunction.setProvider(Optional.ofNullable(this.keyStore.getProvider()).map(Provider::getName).orElse(null));
        this.setTestFunction(testFunction);
        this.residesInHardware = true;
      }
    }

    // Load the private key and certificate ...
    //
    this.loadPrivateKey();

    if (super.getCertificate() == null) {
      Assert.hasText(this.alias, "Property 'alias' must be set");

      final Object[] chain = this.keyStore.getCertificateChain(alias);
      if (chain == null || chain.length == 0) {
        // Just to be sure. Some P11 implementations may not handle chains...
        final X509Certificate cert = (X509Certificate) this.keyStore.getCertificate(this.alias);
        if (cert == null) {
          throw new CertificateException("No certificate found at entry " + this.alias);
        }
        this.setCertificate(cert);
        log.debug("Certificate loaded from entry '{}'", this.alias);
      }
      else {
        this.setCertificateChain(Arrays.stream(chain)
            .map(X509Certificate.class::cast)
            .collect(Collectors.toList()));
        log.debug("Certificate loaded from entry '{}'", this.alias);
      }
    }
  }

  /**
   * Loads the private key from the keystore.
   *
   * @throws Exception for loading errors
   */
  private synchronized void loadPrivateKey() throws Exception {
    Assert.hasText(this.alias, "Property 'alias' must be set");
    if (this.keyPassword == null) {
      if (this.password != null) {
        log.debug("No key password assigned, assuming same password as for keystore ...");
        this.keyPassword = this.password;
      }
    }
    final Key key = this.keyStore.getKey(this.alias, this.keyPassword);
    if (PrivateKey.class.isInstance(key)) {
      super.setPrivateKey(PrivateKey.class.cast(key));
      log.trace("Private key loaded from entry '{}'", this.alias);
    }
    else {
      throw new KeyStoreException("No private key found at entry " + this.alias);
    }
  }

  /**
   * Assigns the resource holding the KeyStore to load.
   *
   * @param resource KeyStore resource
   */
  public void setResource(final Resource resource) {
    if (this.keyStoreFactory == null) {
      this.keyStoreFactory = new KeyStoreFactoryBean();
    }
    this.keyStoreFactory.setResource(resource);
  }

  /**
   * Assigns the KeyStore type to use, ("JKS", "PKCS12", "PKCS11", ...). If no type is configured
   * {@link KeyStore#getDefaultType()} is assumed.
   *
   * @param type the KeyStore type
   */
  public void setType(final String type) {
    if (this.keyStoreFactory == null) {
      this.keyStoreFactory = new KeyStoreFactoryBean();
    }
    this.keyStoreFactory.setType(type);
  }

  /**
   * Assigns the name of the security provider to use when loading the KeyStore. If no provider is assigned, the first
   * provider that can create a KeyStore according to the given type is used.
   *
   * @param provider the provider name to use
   */
  public void setProvider(final String provider) {
    if (this.keyStoreFactory == null) {
      this.keyStoreFactory = new KeyStoreFactoryBean();
    }
    this.keyStoreFactory.setProvider(provider);
  }

  /**
   * Assigns the PKCS#11 configuration file to use.
   * <p>
   * The type ({@link #setType(String)}) must be "PKCS11" and the provider name must be set to the base signature
   * provider to use (e.g. "SunPKCS11").
   * </p>
   *
   * @param pkcs11Configuration the complete path to the PKCS#11 configuration file
   */
  public void setPkcs11Configuration(final String pkcs11Configuration) {
    if (this.keyStoreFactory == null) {
      this.keyStoreFactory = new KeyStoreFactoryBean();
    }
    this.keyStoreFactory.setPkcs11Configuration(pkcs11Configuration);
  }

  /**
   * Assigns the password needed to load the KeyStore.
   *
   * @param password the password
   */
  public void setPassword(final char[] password) {
    if (this.keyStoreFactory == null) {
      this.keyStoreFactory = new KeyStoreFactoryBean();
    }
    this.keyStoreFactory.setPassword(password);
    this.password = Optional.ofNullable(password).map(p -> Arrays.copyOf(p, p.length)).orElse(null);
  }

  /**
   * Assigns the keystore to read the key pair from.
   *
   * @param keyStore the keystore
   */
  public void setKeyStore(final KeyStore keyStore) {
    this.keyStore = keyStore;
  }

  /**
   * Assigns the alias of the KeyStore entry.
   *
   * @param alias the KeyStore alias
   */
  public void setAlias(final String alias) {
    this.alias = alias;
  }

  /**
   * Assigns the key password needed to unlock the key entry.
   *
   * @param keyPassword the key password
   */
  public void setKeyPassword(final char[] keyPassword) {
    this.keyPassword = Optional.ofNullable(keyPassword).map(p -> Arrays.copyOf(p, p.length)).orElse(null);
  }

  /** {@inheritDoc} */
  @Override
  public PublicKey getPublicKey() {
    return Optional.ofNullable(this.getCertificate()).map(X509Certificate::getPublicKey).orElse(null);
  }

  /**
   * Will throw an {@link IllegalArgumentException} since the public key will be read from the keystore.
   */
  @Override
  public void setPublicKey(final PublicKey publicKey) {
    throw new IllegalArgumentException("Assigning the public key for a KeyStoreCredential is not allowed");
  }

  /** {@inheritDoc} */
  @Override
  public synchronized X509Certificate getCertificate() {
    this.getCertificateChain();
    return super.getCertificate();
  }

  /** {@inheritDoc} */
  @Override
  public synchronized List<X509Certificate> getCertificateChain() {
    if (!this.loaded) {
      log.warn("KeyStoreCredential '{}' has not been loaded ...", this.getName());
      try {
        this.load();
      }
      catch (Exception e) {
        log.error("Failed to load KeyStoreCredential '{}'", this.getName(), e);
        throw new SecurityException("Failed to load KeyStoreCredential - " + e.getMessage(), e);
      }
    }
    return super.getCertificateChain();
  }

  /** {@inheritDoc} */
  @Override
  public synchronized PrivateKey getPrivateKey() {
    if (!this.loaded) {
      log.warn("KeyStoreCredential '{}' has not been loaded ...", this.getName());
      try {
        this.load();
      }
      catch (Exception e) {
        log.error("Failed to load KeyStoreCredential '{}'", this.getName(), e);
        throw new SecurityException("Failed to load KeyStoreCredential - " + e.getMessage(), e);
      }
    }
    return super.getPrivateKey();
  }

  /**
   * Will throw an {@link IllegalArgumentException} since the private key will be read from the keystore.
   */
  @Override
  public void setPrivateKey(final PrivateKey privateKey) {
    throw new IllegalArgumentException("Assigning the private key for a KeyStoreCredential is not allowed");
  }

  /**
   * If the {@code KeyStoreCredential} is of PKCS#11 type, the method will reload the private key.
   */
  @Override
  public synchronized void reload() throws Exception {
    //
    // Note: We log only on trace level since the monitor driving the reloading is responsible
    // of the actual logging.
    //
    if (this.keyStore == null) {
      throw new SecurityException("Error in reload - KeyStoreCredential has not been initialized yet");
    }
    if ("PKCS11".equalsIgnoreCase(this.keyStore.getType())) {
      try {
        log.trace("Reloading private key of credential '{}' ...", this.getName());
        this.keyStore.load(null, this.password);
        this.loadPrivateKey();
        log.trace("Reloading private key of credential '{}' successful", this.getName());
      }
      catch (Exception e) {
        log.trace("Failed to reload private key - {}", e.getMessage(), e);
        throw e;
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  protected String getDefaultName() {
    if (this.alias != null) {
      final String type = Optional.ofNullable(this.keyStore).map(KeyStore::getType).orElse(
          Optional.ofNullable(this.keyStoreFactory).map(KeyStoreFactoryBean::getType).orElse(null));

      if ("PKCS11".equalsIgnoreCase(type)) {
        String provider =
            Optional.ofNullable(this.keyStore).map(KeyStore::getProvider).map(Provider::getName).orElse(null);
        if (provider == null) {
          provider = Optional.ofNullable(this.keyStoreFactory).map(KeyStoreFactoryBean::getProvider).orElse(null);
        }
        if (provider != null) {
          return provider + "-" + this.alias;
        }
      }
      return this.alias;
    }
    else {
      return "KeyStoreCredential-" + UUID.randomUUID().toString();
    }
  }

}
