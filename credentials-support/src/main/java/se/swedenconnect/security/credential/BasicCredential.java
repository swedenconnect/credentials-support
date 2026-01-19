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
package se.swedenconnect.security.credential;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.cryptacular.util.KeyPairUtil;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * A basic implementation of the {@link PkiCredential} interface.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class BasicCredential extends AbstractPkiCredential {

  /** The private key. */
  private final PrivateKey privateKey;

  /** The public key - will be {@code null} if certificate is present. */
  private final PublicKey publicKey;

  /** The certificates. */
  private final List<X509Certificate> certificates;

  /**
   * Constructor accepting a {@link KeyPair}.
   *
   * @param keyPair the key pair
   * @throws IllegalArgumentException if key pair is not valid
   */
  public BasicCredential(@Nonnull final KeyPair keyPair) throws IllegalArgumentException {
    this(Objects.requireNonNull(keyPair, "keyPair must not be null").getPublic(), keyPair.getPrivate());
  }

  /**
   * Constructor setting the public and private keys.
   *
   * @param publicKey the public key
   * @param privateKey the private key
   */
  public BasicCredential(@Nonnull final PublicKey publicKey, @Nonnull final PrivateKey privateKey) {
    this.publicKey = Objects.requireNonNull(publicKey, "publicKey must not be null");
    this.privateKey = Objects.requireNonNull(privateKey, "privateKey must not be null");
    this.certificates = null;
  }

  /**
   * Constructor setting the certificate and private key.
   *
   * @param certificate the certificate
   * @param privateKey the private key
   */
  public BasicCredential(@Nonnull final X509Certificate certificate, @Nonnull final PrivateKey privateKey) {
    this.privateKey = Objects.requireNonNull(privateKey, "privateKey must not be null");
    this.certificates = List.of(Objects.requireNonNull(certificate, "certificate must not be null"));
    this.publicKey = null;
    this.updateMetadataValidityProperties();
  }

  /**
   * Constructor assigning a certificate chain and private key.
   *
   * @param certificates the certificate chain where the entity certificate is placed first
   * @param privateKey the private key
   */
  public BasicCredential(@Nonnull final List<X509Certificate> certificates, @Nonnull final PrivateKey privateKey) {
    this.privateKey = Objects.requireNonNull(privateKey, "privateKey must not be null");
    this.certificates =
        Collections.unmodifiableList(Objects.requireNonNull(certificates, "certificates must not be null"));
    this.publicKey = null;

    if (this.certificates.isEmpty()) {
      throw new IllegalArgumentException("certificates must not be empty");
    }
    this.updateMetadataValidityProperties();
  }

  /** {@inheritDoc} */
  @Nonnull
  @Override
  public PrivateKey getPrivateKey() {
    return this.privateKey;
  }

  /** {@inheritDoc} */
  @Nonnull
  @Override
  public List<X509Certificate> getCertificateChain() {
    return Optional.ofNullable(this.certificates).orElse(Collections.emptyList());
  }

  @Override
  @Nullable
  protected PublicKey getStandalonePublicKey() {
    return this.publicKey;
  }

  /**
   * Gets the certificate serial number, and if no certificate is available a UUID is used.
   */
  @Override
  @Nonnull
  protected String getDefaultName() {
    return Optional.ofNullable(this.getCertificate())
        .map(c -> c.getSerialNumber().toString(10))
        .orElseGet(() -> "%s-%s".formatted(this.getPublicKey().getAlgorithm(), UUID.randomUUID()));
  }

}
