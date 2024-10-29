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
import se.swedenconnect.security.credential.pkcs11.Pkcs11Configuration;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.cert.CertificateException;
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
      throw new IllegalArgumentException("PKCS11 keystore type not supported - by createKeyStore");
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

    try {
      final KeyStore keyStore = KeyStore.getInstance(PKCS11_KEYSTORE_TYPE, provider.getName());
      keyStore.load(null, pin);
      return keyStore;
    }
    catch (final NoSuchAlgorithmException | CertificateException | IOException | NoSuchProviderException e) {
      throw new KeyStoreException(e.getMessage(), e);
    }
  }

}
