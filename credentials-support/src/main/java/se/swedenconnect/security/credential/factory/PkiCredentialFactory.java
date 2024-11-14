/*
 * Copyright 2020-2024 Sweden Connect
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
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.KeyStoreReloader;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.config.ConfigurationResourceLoader;
import se.swedenconnect.security.credential.config.DefaultConfigurationResourceLoader;
import se.swedenconnect.security.credential.config.PemCredentialConfiguration;
import se.swedenconnect.security.credential.config.PkiCredentialConfiguration;
import se.swedenconnect.security.credential.config.StoreCredentialConfiguration;
import se.swedenconnect.security.credential.monitoring.DefaultCredentialTestFunction;
import se.swedenconnect.security.credential.pkcs11.Pkcs11KeyStoreReloader;
import se.swedenconnect.security.credential.utils.PrivateKeyUtils;
import se.swedenconnect.security.credential.utils.X509Utils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

/**
 * Factory class for creating {@link PkiCredential} instances.
 *
 * @author Martin Lindström
 */
public class PkiCredentialFactory {

  /** Logger instance. */
  private static final Logger log = LoggerFactory.getLogger(PkiCredentialFactory.class);

  /**
   * Creates a {@link PkiCredential} based on the supplied {@link PkiCredentialConfiguration}.
   *
   * @param configuration the configuration
   * @param resourceLoader loader for readning files, if {@code null}, a {@link DefaultConfigurationResourceLoader}
   *     will be used
   * @param keyStoreSupplier if store references are used, a function that resolves references to key stores must be
   *     supplied
   * @param keyStoreReloaderSupplier if store references are used, and those key stores are "reloadable", a function
   *     that resolves references to a {@link KeyStoreReloader} may be supplied. If not, credentials will not be
   *     reloadable
   * @return a {@link PkiCredential}
   * @throws IllegalArgumentException for invalid configuration settings
   * @throws IOException if a referenced file can not be read
   * @throws CertificateException for certificate decoding errors
   * @throws KeyException for key decoding errors
   * @throws KeyStoreException for errors unlocking the key store
   * @throws NoSuchProviderException if a referenced provider does not exist
   */
  @Nonnull
  public static PkiCredential createCredential(
      @Nonnull final PkiCredentialConfiguration configuration,
      @Nullable final ConfigurationResourceLoader resourceLoader,
      @Nullable final Function<String, KeyStore> keyStoreSupplier,
      @Nullable final Function<String, KeyStoreReloader> keyStoreReloaderSupplier)
      throws IllegalArgumentException, IOException, CertificateException, KeyException, KeyStoreException,
      NoSuchProviderException {

    if (configuration.jks().isPresent()) {
      if (configuration.pem().isPresent()) {
        throw new IllegalArgumentException("Invalid credential configuration - both jks and pem can not be present");
      }
      return createCredential(configuration.jks().get(), resourceLoader, keyStoreSupplier, keyStoreReloaderSupplier);
    }
    else if (configuration.pem().isPresent()) {
      return createCredential(configuration.pem().get(), resourceLoader);
    }
    else {
      throw new IllegalArgumentException("Invalid credential configuration - one of jks or pem must be present");
    }
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

    // First handle the certificate(s) ...
    //
    if (configuration.certificates() == null) {
      throw new IllegalArgumentException("No certificate/s assigned");
    }

    final List<X509Certificate> chain;
    if (X509Utils.isInlinedPem(configuration.certificates())) {
      try (final InputStream is = new ByteArrayInputStream(configuration.certificates().getBytes())) {
        chain = X509Utils.decodeCertificateChain(is);
      }
    }
    else {
      try (final InputStream is = rl.getStream(configuration.certificates())) {
        chain = X509Utils.decodeCertificateChain(is);
      }
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
    if (PrivateKeyUtils.isInlinedPem(configuration.privateKey())) {
      try (final InputStream is = new ByteArrayInputStream(configuration.privateKey().getBytes())) {
        privateKey = PrivateKeyUtils.decodePrivateKey(is, keyPassword);
      }
    }
    else {
      try (final InputStream is = rl.getStream(configuration.privateKey())) {
        privateKey = PrivateKeyUtils.decodePrivateKey(is, keyPassword);
      }
    }

    final BasicCredential credential = new BasicCredential(chain, privateKey);
    configuration.name().ifPresent(credential::setName);

    return credential;
  }

  /**
   * Creates a {@link PkiCredential} based on a {@link StoreCredentialConfiguration}.
   *
   * @param configuration the configuration
   * @param resourceLoader loader for readning files, if {@code null}, a {@link DefaultConfigurationResourceLoader}
   *     will be used
   * @param keyStoreSupplier if store references are used, a function that resolves references to key stores must be
   *     supplied
   * @param keyStoreReloaderSupplier if store references are used, and those key stores are "reloadable", a function
   *     that resolves references to a {@link KeyStoreReloader} may be supplied. If not, credentials will not be
   *     reloadable
   * @return a {@link PkiCredential}
   * @throws IllegalArgumentException for invalid configuration settings
   * @throws IOException if a referenced file can not be read
   * @throws KeyStoreException for errors unlocking the key store
   * @throws NoSuchProviderException if a referenced provider does not exist
   * @throws CertificateException for certificate decoding errors
   */
  @Nonnull
  public static PkiCredential createCredential(
      @Nonnull final StoreCredentialConfiguration configuration,
      @Nullable final ConfigurationResourceLoader resourceLoader,
      @Nullable final Function<String, KeyStore> keyStoreSupplier,
      @Nullable final Function<String, KeyStoreReloader> keyStoreReloaderSupplier)
      throws IllegalArgumentException, IOException, KeyStoreException, NoSuchProviderException, CertificateException {

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
      keyStoreReloader = new Pkcs11KeyStoreReloader(configuration.store().get().password().toCharArray());
    }
    else if (configuration.storeReference().isPresent()) {
      if (keyStoreSupplier == null) {
        throw new IllegalArgumentException("No key store supplier provided - can not resolve store reference");
      }
      keyStore = keyStoreSupplier.apply(configuration.storeReference().get());
      if (keyStore == null) {
        throw new IllegalArgumentException(
            "Referenced store '%s' is not present".formatted(configuration.storeReference().get()));
      }
      if (keyStoreReloaderSupplier != null) {
        keyStoreReloader = keyStoreReloaderSupplier.apply(configuration.storeReference().get());
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
    configuration.name().ifPresent(credential::setName);

    final boolean monitor = configuration.monitor()
        .orElseGet(() -> KeyStoreFactory.PKCS11_KEYSTORE_TYPE.equalsIgnoreCase(keyStore.getType()));

    if (monitor) {
      if (keyStoreReloader != null) {
        credential.setTestFunction(new DefaultCredentialTestFunction());
        credential.setReloader(keyStoreReloader);
      }
      else {
        credential.setTestFunction(null);
        log.warn("Credential '{}' was configured to be monitored, but no reloader is present", credential.getName());
      }
    }
    else {
      credential.setTestFunction(null);
    }

    return credential;
  }

  // Hidden constructor
  private PkiCredentialFactory() {
  }
}
