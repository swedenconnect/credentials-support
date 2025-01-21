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
package se.swedenconnect.security.credential.pkcs11;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.swedenconnect.security.credential.factory.KeyStoreFactory;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * An implementation of the {@link Pkcs11CertificatesAccessor} interface for the SunPKCS11 security provider and other
 * providers that implement the Java {@link java.security.KeyStoreSpi}.
 *
 * @author Martin Lindström
 */
public class SunPkcs11CertificatesAccessor implements Pkcs11CertificatesAccessor {

  /** Logger instance. */
  private static final Logger log = LoggerFactory.getLogger(SunPkcs11CertificatesAccessor.class);

  /** {@inheritDoc} */
  @Nullable
  @Override
  public X509Certificate[] get(@Nonnull final Provider provider, @Nonnull final String alias, @Nonnull final char[] pin)
      throws SecurityException {
    try {
      log.debug("Creating a PKCS11 KeyStore using provider '{}' ...", provider.getName());
      final KeyStore keyStore = KeyStore.getInstance(KeyStoreFactory.PKCS11_KEYSTORE_TYPE, provider);

      log.debug("Loading KeyStore using supplied PIN ...");
      keyStore.load(null, pin);

      log.debug("Getting certificate(s) from entry '{}' ...", alias);
      final X509Certificate[] chain = this.get(keyStore, alias);

      if (chain != null && chain.length > 0) {
        log.debug("Certificate(s) were successfully obtained from device at alias '{}' using provider '{}'",
            alias, provider.getName());
        return chain;
      }
      else {
        log.debug("No certificates were found on device at alias '{}' using provider '{}'", alias, provider.getName());
        return null;
      }
    }
    catch (final Exception e) {
      throw new SecurityException(
          "Failed to load certificates from provider '%s' - %s".formatted(provider.getName(), e.getMessage()), e);
    }
  }

  /**
   * Gets the certificates from the PKCS#11 keystore at the given alias/slot.
   *
   * @param keyStore the keystore
   * @param alias the alias
   * @return a certificate chain for the alias, where the entity certificate must be placed first in the resulting
   *     array, or {@code null} if no certificates are present
   * @throws KeyStoreException for errors accessing the entry
   */
  @Nullable
  public X509Certificate[] get(@Nonnull final KeyStore keyStore, @Nonnull final String alias) throws KeyStoreException {

    final Object[] chain = keyStore.getCertificateChain(alias);
    if (chain != null || chain.length > 0) {
      return Arrays.stream(chain)
          .map(X509Certificate.class::cast)
          .toArray(X509Certificate[]::new);
    }
    else {
      final X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
      if (alias != null) {
        return new X509Certificate[] { cert };
      }
      else {
        return null;
      }
    }
  }

}
