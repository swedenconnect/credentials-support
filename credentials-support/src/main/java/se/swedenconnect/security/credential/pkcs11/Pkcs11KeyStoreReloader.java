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
package se.swedenconnect.security.credential.pkcs11;

import jakarta.annotation.Nonnull;
import jakarta.annotation.PreDestroy;
import se.swedenconnect.security.credential.factory.KeyStoreFactory;

import java.io.IOException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Objects;

/**
 * When a {@link se.swedenconnect.security.credential.KeyStoreCredential KeyStoreCredential} is used with an underlying
 * PKCS#11 {@link }KeyStore} the implementation may want to reload the {@link KeyStore}. This class provides this
 * function.
 *
 * @author Martin Lindström
 */
public class Pkcs11KeyStoreReloader {

  /** The PIN needed to reload the Keystore. */
  private final char[] pin;

  /**
   * Constructor assigning the PIN code.
   *
   * @param pin the HSM PIN
   */
  public Pkcs11KeyStoreReloader(@Nonnull final char[] pin) {
    this.pin = new char[Objects.requireNonNull(pin, "pin must not be null").length];
    System.arraycopy(pin, 0, this.pin, 0, pin.length);
  }

  /**
   * Reloads a PKCS#11 {@link KeyStore}.
   *
   * @param keyStore the PKCS#11 {@link KeyStore}
   * @throws CertificateException for certificate related errors
   * @throws IOException for errors loading the store
   * @throws NoSuchAlgorithmException algorithm errors
   */
  public void reload(final KeyStore keyStore) throws CertificateException, IOException, NoSuchAlgorithmException {
    if (!KeyStoreFactory.PKCS11_KEYSTORE_TYPE.equalsIgnoreCase(keyStore.getType())) {
      throw new IllegalArgumentException("Not a PKCS11 keystore: " + keyStore.getType());
    }
    keyStore.load(null, this.pin);
  }

  /**
   * Method that clears the PIN-code. Will be automatically invoked if the instance is a bean controlled by a framework
   * that manages bean (Spring, Quarkus, ...).
   */
  @PreDestroy
  public void destroy() {
    if (this.pin != null) {
      Arrays.fill(this.pin, (char) 0);
    }
  }
}
