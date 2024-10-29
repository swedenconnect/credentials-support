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
package se.swedenconnect.security.credential;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * A representation of a PKI key pair that holds a private key and an X.509 certificate (or just a public key).
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface PkiCredential {

  /**
   * Gets the public key.
   *
   * @return the public key
   */
  @Nonnull
  PublicKey getPublicKey();

  /**
   * Gets the certificate holding the public key of the key pair. May be {@code null} depending on whether certificates
   * are handled by the implementing class.
   *
   * @return the certificate, or {@code null} if no certificate is configured for the credential
   */
  @Nullable
  default X509Certificate getCertificate() {
    return this.getCertificateChain().stream()
        .findFirst()
        .orElse(null);
  }

  /**
   * Gets a certificate chain for the credential, where the first element is the entity certificate
   * ({@link #getCertificate()}). If no certificate is configured for the credential an empty list is returned.
   *
   * @return a list of certificates, or an empty list
   */
  @Nonnull
  List<X509Certificate> getCertificateChain();

  /**
   * Gets the private key.
   *
   * @return the private key
   */
  @Nonnull
  PrivateKey getPrivateKey();

  /**
   * Gets the name of the credential.
   *
   * @return the name
   */
  @Nonnull
  String getName();

  /**
   * Predicate that tells whether this credential resides in a hardware module.
   *
   * @return {@code true} if the credential resides in a hardware module and {@code false} otherwise
   */
  default boolean isHardwareCredential() {
    return false;
  }

  /**
   * Optional destroy method for credentials that need to perform cleaning up.
   */
  default void destroy() {
  }

}
