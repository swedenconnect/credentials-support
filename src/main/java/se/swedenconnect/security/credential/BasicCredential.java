/*
 * Copyright 2020 Sweden Connect
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

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.UUID;

/**
 * A basic implementation of the {@link KeyPairCredential} interface.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class BasicCredential implements KeyPairCredential {

  /** The private key. */
  private PrivateKey privateKey;

  /** The certificate. */
  private X509Certificate certificate;

  /** The public key. */
  private PublicKey publicKey;

  /** The credential name. */
  private String name;

  /**
   * Constructor setting the public and private keys.
   * 
   * @param publicKey
   *          the public key
   * @param privateKey
   *          the private key
   */
  public BasicCredential(final PublicKey publicKey, final PrivateKey privateKey) {
    this.publicKey = Optional.ofNullable(publicKey).orElseThrow(() -> new IllegalArgumentException("publicKey must not be null"));
    this.privateKey = Optional.ofNullable(privateKey).orElseThrow(() -> new IllegalArgumentException("privateKey must not be null"));
  }

  /**
   * Constructor setting the certificate and private key.
   * 
   * @param certificate
   *          the certificate
   * @param privateKey
   *          the private key
   */
  public BasicCredential(final X509Certificate certificate, final PrivateKey privateKey) {
    this.certificate = Optional.ofNullable(certificate).orElseThrow(() -> new IllegalArgumentException("certificate must not be null"));
    this.privateKey = Optional.ofNullable(privateKey).orElseThrow(() -> new IllegalArgumentException("privateKey must not be null"));
  }

  /** {@inheritDoc} */
  @Override
  public PublicKey getPublicKey() {
    return this.certificate != null ? this.certificate.getPublicKey() : this.publicKey;
  }

  /** {@inheritDoc} */
  @Override
  public X509Certificate getCertificate() {
    return this.certificate;
  }

  /** {@inheritDoc} */
  @Override
  public PrivateKey getPrivateKey() {
    return this.privateKey;
  }

  /**
   * Gets the name. If not explicitly assigned, the subject DN of the certificate is used, and if no certificate is
   * available an UUID is used.
   */
  @Override
  public String getName() {
    if (this.name == null) {
      if (this.certificate != null) {
        this.name = this.certificate.getSubjectX500Principal().getName();
      }
      else {
        this.name = String.format("%s-%s", this.getPublicKey().getAlgorithm(), UUID.randomUUID());
      }
    }
    return this.name;
  }

  /**
   * Assigns the credential name.
   * 
   * @param name
   *          the name
   */
  public void setName(final String name) {
    this.name = name;
  }

}
