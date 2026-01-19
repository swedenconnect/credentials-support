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
package se.swedenconnect.security.credential.factory;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.swedenconnect.security.credential.config.ConfigurationResourceLoader;
import se.swedenconnect.security.credential.config.DefaultConfigurationResourceLoader;
import se.swedenconnect.security.credential.config.StoreConfiguration;
import se.swedenconnect.security.credential.pkcs11.AbstractSunPkcs11Configuration;
import se.swedenconnect.security.credential.pkcs11.CustomPkcs11Configuration;
import se.swedenconnect.security.credential.pkcs11.FilePkcs11Configuration;
import se.swedenconnect.security.credential.pkcs11.Pkcs11Configuration;
import se.swedenconnect.security.credential.pkcs11.Pkcs11ConfigurationException;
import se.swedenconnect.security.credential.pkcs11.StaticPkcs11Configuration;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.Optional;

/**
 * Factory class for loading and unlocking a {@link KeyStore}.
 *
 * @author Martin Lindström
 */
public class KeyStoreFactory {

  /** Logging instance. */
  private static final Logger log = LoggerFactory.getLogger(KeyStoreFactory.class);

  /** Symbolic constant for the PKCS11 KeyStore type. */
  public static final String PKCS11_KEYSTORE_TYPE = "PKCS11";

  /**
   * Loads and unlocks a {@link KeyStore}.
   * <p>
   * To create a {@link KeyStore} for a PKCS#11 device, use {@link #loadPkcs11KeyStore(Pkcs11Configuration, char[])}.
   * </p>
   *
   * @param stream an {@link InputStream} pointing at the key store (if {@code null} an empty {@link KeyStore} will
   *     be created)
   * @param password the password for unlocking the key store (may be {@code null})
   * @param type the key store type, if not supplied, {@link KeyStore#getDefaultType()} will be assumed
   * @param provider the security provider to use (if not provided, the default provider will be used)
   * @return a loaded and unlocked {@link KeyStore}
   * @throws KeyStoreException for errors during loading and unlocking of the key store
   * @throws NoSuchProviderException if the given provider does not exist
   */
  @Nonnull
  public static KeyStore loadKeyStore(@Nullable final InputStream stream, @Nullable final char[] password,
      @Nullable final String type, @Nullable final String provider) throws KeyStoreException, NoSuchProviderException {

    if (PKCS11_KEYSTORE_TYPE.equalsIgnoreCase(type)) {
      log.error("Attempt to create PKCS11 KeyStore using createKeyStore - use createPkcs11KeyStore instead");
      throw new IllegalArgumentException("PKCS11 keystore type not supported by createKeyStore");
    }

    final String keyStoreType = Optional.ofNullable(type).orElseGet(KeyStore::getDefaultType);

    final KeyStore keyStore = provider != null
        ? KeyStore.getInstance(keyStoreType, provider)
        : KeyStore.getInstance(keyStoreType);

    try {
      keyStore.load(stream, password);
      return keyStore;
    }
    catch (final NoSuchAlgorithmException | CertificateException | IOException e) {
      throw new KeyStoreException(e.getMessage(), e);
    }
  }

  /**
   * Loads and unlocks a PKCS#11 key store.
   *
   * @param pkcs11Configuration the PKCS#11 configuration
   * @param pin the PIN to unlock the key store
   * @return a loaded and unlocked {@link KeyStore}
   * @throws KeyStoreException for errors during loading and unlocking of the key store
   */
  @Nonnull
  public static KeyStore loadPkcs11KeyStore(@Nonnull final Pkcs11Configuration pkcs11Configuration,
      @Nonnull final char[] pin) throws KeyStoreException {

    final Provider provider = pkcs11Configuration.getProvider();
    log.debug("Loading PKCS#11 KeyStore using provider '{}'",
        Optional.ofNullable(provider.getName()).orElse("-"));

    try {
      final KeyStore keyStore = KeyStore.getInstance(PKCS11_KEYSTORE_TYPE, provider);
      keyStore.load(null, pin);

      log.debug("Loaded PKCS#11 KeyStore. Aliases: {}", Optional.ofNullable(keyStore.aliases())
          .map(Collections::list)
          .orElse(null));

      return keyStore;
    }
    catch (final NoSuchAlgorithmException | CertificateException | IOException e) {
      throw new KeyStoreException(e.getMessage(), e);
    }
  }

  /**
   * Given a {@link StoreConfiguration} object, this method loads and unlocks a {@link KeyStore}.
   *
   * @param storeConfiguration the configuration object
   * @param resourceLoader for reading configuration resources into {@link InputStream}s, if {@code null}, a
   *     {@link DefaultConfigurationResourceLoader} will be used
   * @return a {@link KeyStore}
   * @throws IllegalArgumentException for missing or illegal input values
   * @throws KeyStoreException for problems unlocking the key store
   * @throws NoSuchProviderException if a reference security provider does not exist
   * @throws IOException for errors reading files referenced in the configuration
   * @throws Pkcs11ConfigurationException for invalid PKCS#11 configuration
   */
  @Nonnull
  public static KeyStore loadKeyStore(
      @Nonnull final StoreConfiguration storeConfiguration, @Nullable final ConfigurationResourceLoader resourceLoader)
      throws IllegalArgumentException, KeyStoreException, NoSuchProviderException, IOException,
      Pkcs11ConfigurationException {

    // The password is required for all types of key stores ...
    //
    final char[] pw = Optional.ofNullable(storeConfiguration.password())
        .map(String::toCharArray)
        .orElseThrow(() -> new IllegalArgumentException("password must be set"));

    if (storeConfiguration.location().isEmpty()) {
      final String type = storeConfiguration.type()
          .orElseGet(() -> storeConfiguration.pkcs11().isPresent() ? KeyStoreFactory.PKCS11_KEYSTORE_TYPE : null);
      if (KeyStoreFactory.PKCS11_KEYSTORE_TYPE.equals(type)) {
        return KeyStoreFactory.loadPkcs11KeyStore(buildPkcs11Configuration(storeConfiguration), pw);
      }
      else {
        throw new IllegalArgumentException("location must be set");
      }
    }
    else {
      return KeyStoreFactory.loadKeyStore(
          Optional.ofNullable(resourceLoader).orElseGet(DefaultConfigurationResourceLoader::new)
              .getStream(storeConfiguration.location().get()), pw,
          storeConfiguration.type().orElse(null), storeConfiguration.provider().orElse(null));
    }
  }

  /**
   * Based on the supplied configuration, a {@link Pkcs11Configuration} object is created.
   *
   * @param configuration the store configuration
   * @return a {@link Pkcs11Configuration} object
   * @throws IllegalArgumentException for missing configuration settings
   * @throws Pkcs11ConfigurationException for PKCS#11 configuration errors
   */
  @Nonnull
  private static Pkcs11Configuration buildPkcs11Configuration(@Nonnull final StoreConfiguration configuration)
      throws IllegalArgumentException, Pkcs11ConfigurationException {

    final AbstractSunPkcs11Configuration pkcs11ConfigurationObject;

    if (configuration.pkcs11().isEmpty()) {
      // This means that the configuration points at an already configured provider ...
      //
      if (configuration.provider().isEmpty()) {
        log.info("No PKCS#11 configuration supplied - assuming that SunPKCS11 provider is statically configured");
      }
      pkcs11ConfigurationObject = new StaticPkcs11Configuration(configuration.provider().orElse(null));
    }
    else {
      final StoreConfiguration.Pkcs11Configuration pkcs11 = configuration.pkcs11().get();
      if (pkcs11.configurationFile().isPresent()) {
        pkcs11ConfigurationObject =
            new FilePkcs11Configuration(pkcs11.configurationFile().get(), configuration.provider().orElse(null));
      }
      else if (pkcs11.settings().isPresent()) {
        final StoreConfiguration.Pkcs11Configuration.Pkcs11Settings settings = pkcs11.settings().get();
        if (settings.name() == null || settings.library() == null) {
          throw new IllegalArgumentException(
              "Invalid custom PKCS#11 configuration - name and library must be supplied");
        }
        pkcs11ConfigurationObject = new CustomPkcs11Configuration(settings.library(), settings.name(),
            settings.slot().orElse(null), settings.slotListIndex().orElse(null), configuration.provider().orElse(null));
      }
      else {
        throw new IllegalArgumentException("Invalid PKCS#11 configuration - could not create provider");
      }
    }

    pkcs11ConfigurationObject.init();
    return pkcs11ConfigurationObject;
  }

}
