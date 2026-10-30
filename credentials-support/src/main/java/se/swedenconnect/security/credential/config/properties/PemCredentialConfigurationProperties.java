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
package se.swedenconnect.security.credential.config.properties;

import jakarta.annotation.Nullable;
import se.swedenconnect.security.credential.config.PemCredentialConfiguration;

import java.util.Objects;
import java.util.Optional;

/**
 * Configuration properties for creating a {@link se.swedenconnect.security.credential.PkiCredential PkiCredential}
 * using PEM-encoded certificate(s) and private keys.
 *
 * @author Martin Lindström
 */
public class PemCredentialConfigurationProperties extends AbstractBaseCredentialConfigurationProperties implements
    PemCredentialConfiguration {

  /**
   * Location or content of the public key in PEM format. This setting is mutually exclusive with the certificates
   * setting.
   */
  private String publicKey;

  /**
   * Location or content of the certificate or certificate chain in PEM format. If more than one certificate is
   * supplied, the entity certificate, i.e., the certificate holding the public key of the key pair, must be placed
   * first. This setting is mutually exclusive with the public-key setting.
   */
  private String certificates;

  /**
   * Location or content of the private key in PEM format.
   */
  private String privateKey;

  /**
   * Password used to decrypt the private key (if this is given in encrypted format).
   */
  private String keyPassword;

  /**
   * Gets the location or content of the public key in PEM format.
   *
   * @return the public key location or content
   */
  @Nullable
  public String getPublicKey() {
    return this.publicKey;
  }

  /**
   * Assigns the location or content of the public key in PEM format.
   *
   * @param publicKey the public key location or content
   */
  public void setPublicKey(@Nullable final String publicKey) {
    this.publicKey = publicKey;
  }

  /**
   * Gets the location or content of the certificate or certificate chain in PEM format.
   *
   * @return the certificate(s) location or content
   */
  @Nullable
  public String getCertificates() {
    return this.certificates;
  }

  /**
   * Assigns the location or content of the certificate or certificate chain in PEM format.
   *
   * @param certificates the certificate(s) location or content
   */
  public void setCertificates(@Nullable final String certificates) {
    this.certificates = certificates;
  }

  /**
   * Gets the location or content of the private key in PEM format.
   *
   * @return the private key location or content
   */
  @Nullable
  public String getPrivateKey() {
    return this.privateKey;
  }

  /**
   * Assigns the location or content of the private key in PEM format.
   *
   * @param privateKey the private key location or content
   */
  public void setPrivateKey(@Nullable final String privateKey) {
    this.privateKey = privateKey;
  }

  /**
   * Gets the password used to decrypt the private key.
   *
   * @return the private key password
   */
  @Nullable
  public String getKeyPassword() {
    return this.keyPassword;
  }

  /**
   * Assigns the password used to decrypt the private key.
   *
   * @param keyPassword the private key password
   */
  public void setKeyPassword(@Nullable final String keyPassword) {
    this.keyPassword = keyPassword;
  }

  /** {@inheritDoc} */
  @Override
  public Optional<String> publicKey() {
    return Optional.ofNullable(this.publicKey);
  }

  /** {@inheritDoc} */
  @Override
  public Optional<String> certificates() {
    return Optional.ofNullable(this.certificates);
  }

  /** {@inheritDoc} */
  @Override
  public String privateKey() {
    return this.getPrivateKey();
  }

  /** {@inheritDoc} */
  @Override
  public Optional<String> keyPassword() {
    return Optional.ofNullable(this.getKeyPassword());
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || this.getClass() != o.getClass()) {
      return false;
    }
    if (!super.equals(o)) {
      return false;
    }
    final PemCredentialConfigurationProperties that = (PemCredentialConfigurationProperties) o;
    return Objects.equals(this.publicKey, that.publicKey) && Objects.equals(this.certificates,
        that.certificates) && Objects.equals(this.privateKey, that.privateKey) && Objects.equals(
        this.keyPassword, that.keyPassword);
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hash(super.hashCode(), this.publicKey, this.certificates, this.privateKey, this.keyPassword);
  }

}
