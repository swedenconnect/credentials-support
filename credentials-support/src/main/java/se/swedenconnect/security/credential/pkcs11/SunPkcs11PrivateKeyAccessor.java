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
package se.swedenconnect.security.credential.pkcs11;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.swedenconnect.security.credential.factory.KeyStoreFactory;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.UnrecoverableKeyException;

/**
 * An implementation of the {@link Pkcs11PrivateKeyAccessor} interface for the SunPKCS11 security provider and other
 * providers that implement the Java {@link java.security.KeyStoreSpi}.
 *
 * @author Martin Lindström
 */
public class SunPkcs11PrivateKeyAccessor implements Pkcs11PrivateKeyAccessor {

  /** Logger instance. */
  private static final Logger log = LoggerFactory.getLogger(SunPkcs11PrivateKeyAccessor.class);

  /** {@inheritDoc} */
  @Nonnull
  @Override
  public PrivateKey get(@Nonnull final Provider provider, @Nonnull final String alias, @Nonnull final char[] pin)
      throws SecurityException {
    try {
      log.debug("Creating a PKCS11 KeyStore using provider '{}' ...", provider.getName());
      final KeyStore keyStore = KeyStore.getInstance(KeyStoreFactory.PKCS11_KEYSTORE_TYPE, provider);

      log.debug("Loading KeyStore using supplied PIN ...");
      keyStore.load(null, pin);

      log.debug("Getting private key from entry '{}' ...", alias);
      final PrivateKey pk = this.get(keyStore, alias, pin);

      if (pk != null) {
        log.debug("Private key was successfully obtained from device at alias '{}' using provider '{}'",
            alias, provider.getName());
        return pk;
      }
      else {
        throw new SecurityException("No private key was found on device at alias '%s' using provider '%s'"
            .formatted(alias, provider.getName()));
      }
    }
    catch (final Exception e) {
      throw new SecurityException(
          "Failed to load private key from provider '%s' - %s".formatted(provider.getName(), e.getMessage()), e);
    }
  }

  /**
   * Gets the private key from the given entry (identified by {@code alias}).
   *
   * @param keyStore the keystore
   * @param alias the entry alias
   * @param pin the PIN to unlock the key
   * @return a {@link PrivateKey} or {@code null} if no key is found
   * @throws KeyStoreException for errors accessing the key
   */
  @Nullable
  public PrivateKey get(@Nonnull final KeyStore keyStore, @Nonnull final String alias, @Nonnull final char[] pin)
      throws KeyStoreException {
    try {
      return (PrivateKey) keyStore.getKey(alias, pin);
    }
    catch (final NoSuchAlgorithmException | UnrecoverableKeyException e) {
      throw new KeyStoreException(e.getMessage(), e);
    }
  }
}
