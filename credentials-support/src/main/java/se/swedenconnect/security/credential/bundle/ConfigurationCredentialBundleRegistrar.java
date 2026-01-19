/*
 * Copyright 2020-2026 Sweden Connect
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
package se.swedenconnect.security.credential.bundle;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.swedenconnect.security.credential.KeyStoreReloader;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.config.ConfigurationResourceLoader;
import se.swedenconnect.security.credential.config.CredentialBundlesConfiguration;
import se.swedenconnect.security.credential.config.DefaultConfigurationResourceLoader;
import se.swedenconnect.security.credential.factory.KeyStoreFactory;
import se.swedenconnect.security.credential.factory.PkiCredentialFactory;
import se.swedenconnect.security.credential.pkcs11.Pkcs11KeyStoreReloader;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * A {@link CredentialBundleRegistrar} implementation that registers credentials and key stores based on a configuration
 * object.
 *
 * @author Martin Lindström
 */
public class ConfigurationCredentialBundleRegistrar implements CredentialBundleRegistrar {

  /** Logger instance. */
  private static final Logger log = LoggerFactory.getLogger(ConfigurationCredentialBundleRegistrar.class);

  /** The configuration. */
  private final CredentialBundlesConfiguration configuration;

  /** The resource loader. */
  private final ConfigurationResourceLoader resourceLoader;

  /**
   * Constructor using a {@link DefaultConfigurationResourceLoader} to load resources. Spring and Quarkus users should
   * implement their own resource loaders.
   *
   * @param configuration the configuration to use when registering credentials and key stores
   */
  public ConfigurationCredentialBundleRegistrar(@Nonnull final CredentialBundlesConfiguration configuration) {
    this.configuration = Objects.requireNonNull(configuration, "configuration must not be null");
    this.resourceLoader = new DefaultConfigurationResourceLoader();
  }

  /**
   * Constructor.
   *
   * @param configuration the configuration to use when registering credentials and key stores
   * @param resourceLoader the resource loader for reading resources referenced in the configuration
   */
  public ConfigurationCredentialBundleRegistrar(@Nonnull final CredentialBundlesConfiguration configuration,
      @Nonnull final ConfigurationResourceLoader resourceLoader) {
    this.configuration = Objects.requireNonNull(configuration, "configuration must not be null");
    this.resourceLoader = Objects.requireNonNull(resourceLoader, "resourceLoader must not be null");
  }

  /**
   * Utility method for loading the supplied configuration and registering key stores and credentials at the supplied
   * registry.
   *
   * @param configuration the configuration to use when registering credentials and key stores
   * @param resourceLoader the resource loader for reading resources referenced in the configuration, if
   *     {@code null}, a {@link DefaultConfigurationResourceLoader} will be used
   * @param registry the registry to update
   * @throws IllegalArgumentException for invalid registration/configuration data
   */
  public static void loadConfiguration(@Nonnull final CredentialBundlesConfiguration configuration,
      @Nullable final ConfigurationResourceLoader resourceLoader,
      @Nonnull final CredentialBundleRegistry registry) throws IllegalArgumentException {
    final ConfigurationCredentialBundleRegistrar registrar = resourceLoader != null
        ? new ConfigurationCredentialBundleRegistrar(configuration, resourceLoader)
        : new ConfigurationCredentialBundleRegistrar(configuration);
    registrar.register(registry);
  }

  /** {@inheritDoc} */
  @Override
  public void register(@Nonnull final CredentialBundleRegistry registry) throws IllegalArgumentException {

    // First load key stores ...
    // We keep a local map for all key stores loaded since credentials may reference key stores later ...
    //
    final Map<String, KeyStore> keyStoreMap = new HashMap<>();
    final Map<String, KeyStoreReloader> keyStoreReloaderMap = new HashMap<>();
    this.configuration.keystore().ifPresent(map -> map.forEach((key, value) -> {
      log.debug("Loading key store for entry '{}' ...", key);
      try {
        final KeyStore keyStore = KeyStoreFactory.loadKeyStore(value, this.resourceLoader);
        log.debug("Loaded key store for entry '{}', registering it ...", key);
        registry.registerKeyStore(key, keyStore);
        keyStoreMap.put(key, keyStore);
        if (KeyStoreFactory.PKCS11_KEYSTORE_TYPE.equalsIgnoreCase(keyStore.getType())) {
          keyStoreReloaderMap.put(key, new Pkcs11KeyStoreReloader(value.password().toCharArray()));
        }
        else {
          keyStoreReloaderMap.put(key,
              new FileBasedKeyStoreReloader(value.location().orElse(null), value.password(), this.resourceLoader));
        }
      }
      catch (final KeyStoreException | NoSuchProviderException | IOException e) {
        final String msg = "Error while loading key store for entry '%s' - %s".formatted(key, e.getMessage());
        log.info("{}", msg, e);
        throw new IllegalArgumentException(msg, e);
      }
    }));

    // Next, load the credentials ...
    //
    this.configuration.pem().ifPresent(map -> map.forEach((key, value) -> {
      log.debug("Loading PEM credential '{}' ...", key);
      try {
        final PkiCredential credential = PkiCredentialFactory.createCredential(value, this.resourceLoader);
        log.debug("Loaded credential for entry '{}', registering it ...", key);
        registry.registerCredential(key, credential);
      }
      catch (final IOException | CertificateException | KeyException e) {
        final String msg = "Error while loading credential for entry '%s' - %s".formatted(key, e.getMessage());
        log.info("{}", msg, e);
        throw new IllegalArgumentException(msg, e);
      }
    }));
    this.configuration.jks().ifPresent(map -> {
      map.forEach((key, value) -> {
        log.debug("Loading JKS credential '{}' ...", key);
        try {
          final PkiCredential credential = PkiCredentialFactory.createCredential(value, this.resourceLoader,
              keyStoreMap::get, keyStoreReloaderMap::get);
          log.debug("Loaded credential for entry '{}', registering it ...", key);
          registry.registerCredential(key, credential);
        }
        catch (final IOException | KeyStoreException | NoSuchProviderException | CertificateException e) {
          final String msg = "Error while loading credential for entry '%s' - %s".formatted(key, e.getMessage());
          log.info("{}", msg, e);
          throw new IllegalArgumentException(msg, e);
        }
      });
    });

  }

  /**
   * For re-loading file based key stores. Usually not needed.
   */
  private static class FileBasedKeyStoreReloader implements KeyStoreReloader {

    /** The location to the file based key store. */
    private final String location;

    /** The password needed to reload the Keystore. */
    private final String password;

    /** The resource loader. */
    private final ConfigurationResourceLoader resourceLoader;

    /**
     * Constructor.
     *
     * @param location the location to the file-based key store
     * @param password the key store password
     * @param resourceLoader for loading resources
     */
    public FileBasedKeyStoreReloader(@Nonnull final String location, @Nonnull final String password,
        @Nonnull final ConfigurationResourceLoader resourceLoader) {
      this.location = location;
      this.password = password;
      this.resourceLoader = resourceLoader;
    }

    /** {@inheritDoc} */
    @Override
    public void reload(@Nonnull final KeyStore keyStore) throws KeyStoreException {
      try (final InputStream is = this.resourceLoader.getStream(this.location)) {
        keyStore.load(is, this.password.toCharArray());
      }
      catch (final CertificateException | IOException | NoSuchAlgorithmException e) {
        throw new KeyStoreException(e.getMessage(), e);
      }
    }
  }

}
