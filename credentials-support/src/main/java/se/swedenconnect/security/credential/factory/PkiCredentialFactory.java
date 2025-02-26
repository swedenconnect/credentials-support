/*
 * Copyright 2020-2025 Sweden Connect
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
package se.swedenconnect.security.credential.factory;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.swedenconnect.security.credential.AbstractPkiCredential;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.KeyStoreReloader;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.bundle.CredentialBundles;
import se.swedenconnect.security.credential.bundle.NoSuchCredentialException;
import se.swedenconnect.security.credential.bundle.NoSuchKeyStoreException;
import se.swedenconnect.security.credential.config.BaseCredentialConfiguration;
import se.swedenconnect.security.credential.config.ConfigurationResourceLoader;
import se.swedenconnect.security.credential.config.DefaultConfigurationResourceLoader;
import se.swedenconnect.security.credential.config.PemCredentialConfiguration;
import se.swedenconnect.security.credential.config.PkiCredentialConfiguration;
import se.swedenconnect.security.credential.config.StoreCredentialConfiguration;
import se.swedenconnect.security.credential.monitoring.DefaultCredentialTestFunction;
import se.swedenconnect.security.credential.pkcs11.Pkcs11KeyStoreReloader;
import se.swedenconnect.security.credential.utils.KeyUtils;
import se.swedenconnect.security.credential.utils.X509Utils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Function;

/**
 * Factory class for creating {@link PkiCredential} instances. It can either be used statically, or instantiated with a
 * resource loader and loaders for credentials or keystores (or a credential bundles object).
 *
 * @author Martin Lindström
 */
public class PkiCredentialFactory {

  /** Logger instance. */
  private static final Logger log = LoggerFactory.getLogger(PkiCredentialFactory.class);

  /** For loading credentials. */
  private final Function<String, PkiCredential> credentialProvider;

  /** For loading keystores. */
  private final Function<String, KeyStore> keyStoreProvider;

  /** For loading resources. */
  private final ConfigurationResourceLoader resourceLoader;

  /** Cache for avoiding loading the same credential several times. */
  private ConcurrentMap<Integer, PkiCredential> cache;

  /**
   * Constructor assigning the {@link CredentialBundles}, credential and keystore providers.
   *
   * @param credentialProvider for loading credentials
   * @param keyStoreProvider for loading keystores
   * @param resourceLoader for loading resources
   * @param useCache whether caches will be used
   */
  public PkiCredentialFactory(@Nullable final Function<String, PkiCredential> credentialProvider,
      @Nullable final Function<String, KeyStore> keyStoreProvider,
      @Nullable final ConfigurationResourceLoader resourceLoader, final boolean useCache) {
    this.credentialProvider = credentialProvider;
    this.keyStoreProvider = keyStoreProvider;
    this.resourceLoader = Optional.ofNullable(resourceLoader).orElseGet(DefaultConfigurationResourceLoader::new);
    if (useCache) {
      this.cache = new ConcurrentHashMap<>();
    }
  }

  /**
   * Constructor assigning the {@link CredentialBundles} and {@link ConfigurationResourceLoader}.
   *
   * @param credentialBundles the credentials bundles to use
   * @param resourceLoader for loading resources
   * @param useCache whether caches will be used
   */
  public PkiCredentialFactory(@Nullable final CredentialBundles credentialBundles,
      @Nullable final ConfigurationResourceLoader resourceLoader, final boolean useCache) {
    this(Optional.ofNullable(credentialBundles).map(CredentialBundles::getCredentialProvider).orElse(null),
        Optional.ofNullable(credentialBundles).map(CredentialBundles::getKeyStoreProvider).orElse(null),
        resourceLoader, useCache);
  }

  /**
   * Creates a {@link PkiCredential} based on the supplied {@link PkiCredentialConfiguration}.
   *
   * @param configuration the configuration
   * @param resourceLoader loader for readning files, if {@code null}, a {@link DefaultConfigurationResourceLoader}
   *     will be used
   * @param credentialProvider if the supplied configuration object contains a credential bundle reference, this
   *     provider must be supplied
   * @param keyStoreProvider if the supplied configuration object contains a key store reference, this provider must
   *     be supplied
   * @param keyStoreReloaderProvider if store references are used, and those key stores are "reloadable", a function
   *     that resolves references to a {@link KeyStoreReloader} may be supplied. If not, credentials will not be
   *     reloadable
   * @return a {@link PkiCredential}
   * @throws IllegalArgumentException for invalid configuration settings
   * @throws IOException if a referenced file can not be read
   * @throws NoSuchCredentialException if a bundle is used in the supplied configuration, and it does not exist
   * @throws NoSuchKeyStoreException if a reference to a key store can not be found
   * @throws CertificateException for certificate decoding errors
   * @throws KeyException for key decoding errors
   * @throws KeyStoreException for errors unlocking the key store
   * @throws NoSuchProviderException if a referenced provider does not exist
   */
  @Nonnull
  public static PkiCredential createCredential(
      @Nonnull final PkiCredentialConfiguration configuration,
      @Nullable final ConfigurationResourceLoader resourceLoader,
      @Nullable final Function<String, PkiCredential> credentialProvider,
      @Nullable final Function<String, KeyStore> keyStoreProvider,
      @Nullable final Function<String, KeyStoreReloader> keyStoreReloaderProvider)
      throws IllegalArgumentException, IOException, NoSuchCredentialException, NoSuchKeyStoreException,
      CertificateException, KeyException, KeyStoreException, NoSuchProviderException {

    if (configuration.bundle().isPresent()) {
      if (configuration.jks().isPresent() || configuration.pem().isPresent()) {
        throw new IllegalArgumentException(
            "Invalid credential configuration - if bundle is used, jks or pem can not be present");
      }
      if (credentialProvider == null) {
        throw new IllegalArgumentException("Missing credentialProvider - can not resolve reference");
      }
      final String credentialReference = configuration.bundle().get();
      return Optional.ofNullable(credentialProvider.apply(credentialReference))
          .orElseThrow(() -> new NoSuchCredentialException(credentialReference, "Referenced bundle not found"));
    }
    else if (configuration.jks().isPresent()) {
      if (configuration.pem().isPresent()) {
        throw new IllegalArgumentException("Invalid credential configuration - both jks and pem can not be present");
      }
      return createCredential(configuration.jks().get(), resourceLoader, keyStoreProvider, keyStoreReloaderProvider);
    }
    else if (configuration.pem().isPresent()) {
      return createCredential(configuration.pem().get(), resourceLoader);
    }
    else {
      throw new IllegalArgumentException("Invalid credential configuration - one of jks or pem must be present");
    }
  }

  /**
   * Creates a {@link PkiCredential} based on the supplied {@link PkiCredentialConfiguration}.
   *
   * @param configuration the configuration
   * @return a {@link PkiCredential}
   * @throws IllegalArgumentException for invalid configuration settings
   * @throws IOException if a referenced file can not be read
   * @throws NoSuchCredentialException if a bundle is used in the supplied configuration, and it does not exist
   * @throws NoSuchKeyStoreException if a reference to a key store can not be found
   * @throws CertificateException for certificate decoding errors
   * @throws KeyException for key decoding errors
   * @throws KeyStoreException for errors unlocking the key store
   * @throws NoSuchProviderException if a referenced provider does not exist
   */
  @Nonnull
  public PkiCredential createCredential(@Nonnull final PkiCredentialConfiguration configuration)
      throws IllegalArgumentException, IOException, NoSuchCredentialException, NoSuchKeyStoreException,
      CertificateException, KeyException, KeyStoreException, NoSuchProviderException {

    if (this.cache != null && configuration.bundle().isEmpty()) {
      final PkiCredential c = this.cache.get(configuration.hashCode());
      if (c != null) {
        log.debug("Returning cached credential '{}'", c.getName());
        return c;
      }
    }
    final PkiCredential credential = PkiCredentialFactory.createCredential(configuration, this.resourceLoader,
        this.credentialProvider, this.keyStoreProvider, null);
    Optional.ofNullable(this.cache).ifPresent(c -> c.put(configuration.hashCode(), credential));
    return credential;
  }

  /**
   * Creates a {@link PkiCredential} based on a {@link PemCredentialConfiguration}.
   *
   * @param configuration the configuration
   * @param resourceLoader loader for readning files, if {@code null}, a {@link DefaultConfigurationResourceLoader}
   *     will be used
   * @return a {@link PkiCredential}
   * @throws IllegalArgumentException for invalid configuration settings
   * @throws IOException if a referenced file can not be read
   * @throws CertificateException for certificate decoding errors
   * @throws KeyException for key decoding errors
   */
  @Nonnull
  public static PkiCredential createCredential(@Nonnull final PemCredentialConfiguration configuration,
      @Nullable final ConfigurationResourceLoader resourceLoader)
      throws IllegalArgumentException, IOException, CertificateException, KeyException {

    final ConfigurationResourceLoader rl = Optional.ofNullable(resourceLoader)
        .orElseGet(DefaultConfigurationResourceLoader::new);

    // First handle the certificate(s)/public keys...
    //
    if (configuration.certificates().isPresent() && configuration.publicKey().isPresent()) {
      throw new IllegalArgumentException("Certificate(s) and public key must not both be present");
    }

    final List<X509Certificate> chain;
    final PublicKey publicKey;
    if (configuration.certificates().isPresent()) {
      publicKey = null;
      if (X509Utils.isInlinedPem(configuration.certificates().get())) {
        try (final InputStream is = new ByteArrayInputStream(configuration.certificates().get().getBytes())) {
          chain = X509Utils.decodeCertificateChain(is);
        }
      }
      else {
        try (final InputStream is = rl.getStream(configuration.certificates().get())) {
          chain = X509Utils.decodeCertificateChain(is);
        }
      }
    }
    else if (configuration.publicKey().isPresent()) {
      chain = null;
      if (KeyUtils.isInlinedPem(configuration.publicKey().get())) {
        try (final InputStream is = new ByteArrayInputStream(configuration.publicKey().get().getBytes())) {
          publicKey = KeyUtils.decodePublicKey(is);
        }
      }
      else {
        try (final InputStream is = rl.getStream(configuration.publicKey().get())) {
          publicKey = KeyUtils.decodePublicKey(is);
        }
      }
    }
    else {
      throw new IllegalArgumentException("Missing Certificate(s) or public key");
    }

    // The private key ...
    //
    if (configuration.privateKey() == null) {
      throw new IllegalArgumentException("No private key assigned");
    }
    final PrivateKey privateKey;
    final char[] keyPassword = configuration.keyPassword()
        .map(String::toCharArray)
        .orElse(null);
    if (KeyUtils.isInlinedPem(configuration.privateKey())) {
      try (final InputStream is = new ByteArrayInputStream(configuration.privateKey().getBytes())) {
        privateKey = KeyUtils.decodePrivateKey(is, keyPassword);
      }
    }
    else {
      try (final InputStream is = rl.getStream(configuration.privateKey())) {
        privateKey = KeyUtils.decodePrivateKey(is, keyPassword);
      }
    }

    final BasicCredential credential = chain != null
        ? new BasicCredential(chain, privateKey)
        : new BasicCredential(publicKey, privateKey);

    assignBaseProperties(configuration, credential);

    return credential;
  }

  /**
   * Creates a {@link PkiCredential} based on a {@link PemCredentialConfiguration}.
   *
   * @param configuration the configuration
   * @return a {@link PkiCredential}
   * @throws IllegalArgumentException for invalid configuration settings
   * @throws IOException if a referenced file can not be read
   * @throws CertificateException for certificate decoding errors
   * @throws KeyException for key decoding errors
   */
  @Nonnull
  public PkiCredential createCredential(@Nonnull final PemCredentialConfiguration configuration)
      throws IllegalArgumentException, IOException, CertificateException, KeyException {

    if (this.cache != null) {
      final PkiCredential c = this.cache.get(configuration.hashCode());
      if (c != null) {
        log.debug("Returning cached credential '{}'", c.getName());
        return c;
      }
    }
    final PkiCredential credential = PkiCredentialFactory.createCredential(configuration, this.resourceLoader);
    Optional.ofNullable(this.cache).ifPresent(c -> c.put(configuration.hashCode(), credential));
    return credential;
  }

  /**
   * Creates a {@link PkiCredential} based on a {@link StoreCredentialConfiguration}.
   *
   * @param configuration the configuration
   * @param resourceLoader loader for readning files, if {@code null}, a {@link DefaultConfigurationResourceLoader}
   *     will be used
   * @param keyStoreProvider if store references are used, a function that resolves references to key stores must be
   *     supplied
   * @param keyStoreReloaderProvider if store references are used, and those key stores are "reloadable", a function
   *     that resolves references to a {@link KeyStoreReloader} may be supplied. If not, it will be assumed that the key
   *     store may be reloaded using the key password (which then must be the same as the store password)
   * @return a {@link PkiCredential}
   * @throws IllegalArgumentException for invalid configuration settings
   * @throws IOException if a referenced file can not be read
   * @throws NoSuchKeyStoreException if a reference to a key store can not be found
   * @throws KeyStoreException for errors unlocking the key store
   * @throws NoSuchProviderException if a referenced provider does not exist
   * @throws CertificateException for certificate decoding errors
   */
  @Nonnull
  public static PkiCredential createCredential(
      @Nonnull final StoreCredentialConfiguration configuration,
      @Nullable final ConfigurationResourceLoader resourceLoader,
      @Nullable final Function<String, KeyStore> keyStoreProvider,
      @Nullable final Function<String, KeyStoreReloader> keyStoreReloaderProvider)
      throws IllegalArgumentException, IOException, NoSuchKeyStoreException, KeyStoreException, NoSuchProviderException,
      CertificateException {

    final ConfigurationResourceLoader rl = Optional.ofNullable(resourceLoader)
        .orElseGet(DefaultConfigurationResourceLoader::new);

    // Get the key store ...
    //
    final KeyStore keyStore;
    KeyStoreReloader keyStoreReloader = null;
    if (configuration.store().isPresent()) {
      if (configuration.storeReference().isPresent()) {
        throw new IllegalArgumentException("Both store and store-reference can not be set");
      }
      keyStore = KeyStoreFactory.loadKeyStore(configuration.store().get(), rl);
      if (KeyStoreFactory.PKCS11_KEYSTORE_TYPE.equalsIgnoreCase(keyStore.getType())) {
        keyStoreReloader = new Pkcs11KeyStoreReloader(configuration.store().get().password().toCharArray());
      }
    }
    else if (configuration.storeReference().isPresent()) {
      if (keyStoreProvider == null) {
        throw new IllegalArgumentException("No key store provider provided - can not resolve store reference");
      }
      keyStore = keyStoreProvider.apply(configuration.storeReference().get());
      if (keyStore == null) {
        throw new NoSuchKeyStoreException(configuration.storeReference().get(),
            "Referenced store '%s' is not present".formatted(configuration.storeReference().get()));
      }
      if (keyStoreReloaderProvider != null) {
        keyStoreReloader = keyStoreReloaderProvider.apply(configuration.storeReference().get());
      }
    }
    else {
      throw new IllegalArgumentException("No store or store-reference assigned");
    }

    // Next, get the key entry ...
    //
    if (configuration.key() == null) {
      throw new IllegalArgumentException("No key entry assigned");
    }
    final String alias = Optional.ofNullable(configuration.key().alias())
        .orElseThrow(() -> new IllegalArgumentException("No key entry alias assigned"));

    final char[] keyPassword;
    if (configuration.key().keyPassword().isPresent()) {
      keyPassword = configuration.key().keyPassword().get().toCharArray();
    }
    else {
      if (configuration.store().isPresent()) {
        keyPassword = configuration.store().get().password().toCharArray();
      }
      else {
        throw new IllegalArgumentException(
            "No key password given, and can not get store password since store reference was used");
      }
    }

    // Any certificates supplied?
    //
    final List<X509Certificate> chain;
    if (configuration.key().certificates().isPresent()) {
      if (X509Utils.isInlinedPem(configuration.key().certificates().get())) {
        try (final InputStream is = new ByteArrayInputStream(configuration.key().certificates().get().getBytes())) {
          chain = X509Utils.decodeCertificateChain(is);
        }
      }
      else {
        try (final InputStream is = rl.getStream(configuration.key().certificates().get())) {
          chain = X509Utils.decodeCertificateChain(is);
        }
      }
    }
    else {
      chain = null;
    }

    final KeyStoreCredential credential = new KeyStoreCredential(keyStore, alias, keyPassword, chain);
    assignBaseProperties(configuration, credential);

    final boolean monitor = configuration.monitor()
        .orElseGet(() -> KeyStoreFactory.PKCS11_KEYSTORE_TYPE.equalsIgnoreCase(keyStore.getType()));

    if (monitor) {
      credential.setTestFunction(new DefaultCredentialTestFunction());
      Optional.ofNullable(keyStoreReloader).ifPresent(credential::setReloader);
    }
    else {
      credential.setTestFunction(null);
    }

    return credential;
  }

  /**
   * Creates a {@link PkiCredential} based on a {@link StoreCredentialConfiguration}.
   *
   * @param configuration the configuration
   * @return a {@link PkiCredential}
   * @throws IllegalArgumentException for invalid configuration settings
   * @throws IOException if a referenced file can not be read
   * @throws NoSuchKeyStoreException if a reference to a key store can not be found
   * @throws KeyStoreException for errors unlocking the key store
   * @throws NoSuchProviderException if a referenced provider does not exist
   * @throws CertificateException for certificate decoding errors
   */
  @Nonnull
  public PkiCredential createCredential(@Nonnull final StoreCredentialConfiguration configuration)
      throws IllegalArgumentException, IOException, NoSuchKeyStoreException, KeyStoreException, NoSuchProviderException,
      CertificateException {

    if (this.cache != null) {
      final PkiCredential c = this.cache.get(configuration.hashCode());
      if (c != null) {
        log.debug("Returning cached credential '{}'", c.getName());
        return c;
      }
    }
    final PkiCredential credential = PkiCredentialFactory.createCredential(configuration, this.resourceLoader,
        this.keyStoreProvider, null);
    Optional.ofNullable(this.cache).ifPresent(c -> c.put(configuration.hashCode(), credential));
    return credential;
  }

  /**
   * Assigns common credential properties.
   *
   * @param configuration the configuration
   * @param credential the credential to update
   * @param <T> the credential type
   */
  private static <T extends AbstractPkiCredential> void assignBaseProperties(
      @Nonnull final BaseCredentialConfiguration configuration, @Nonnull final T credential) {
    configuration.name().ifPresent(credential::setName);
    configuration.metadata().ifPresent(
        c -> c.forEach((key, value) -> credential.getMetadata().getProperties().put(key, value)));
    configuration.keyId().ifPresent(
        c -> credential.getMetadata().getProperties().put(PkiCredential.Metadata.KEY_ID_PROPERTY, c));
    configuration.issuedAt().ifPresent(
        c -> credential.getMetadata().getProperties().put(PkiCredential.Metadata.ISSUED_AT_PROPERTY, c));
    configuration.expiresAt().ifPresent(
        c -> credential.getMetadata().getProperties().put(PkiCredential.Metadata.EXPIRES_AT_PROPERTY, c));
  }

}
