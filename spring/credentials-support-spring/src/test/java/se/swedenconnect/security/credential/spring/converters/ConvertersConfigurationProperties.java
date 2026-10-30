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
package se.swedenconnect.security.credential.spring.converters;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Objects;

/**
 * Configuration properties for converter tests.
 *
 * @author Martin Lindström
 */
@ConfigurationProperties("convertertest")
public class ConvertersConfigurationProperties {

  private PrivateKey pkcs8Key;

  private PrivateKey opensslKey;

  private X509Certificate cert;

  private PublicKey publicKey;

  private PublicKey publicKey2;

  /**
   * Gets the {@code pkcs8Key} property.
   *
   * @return the {@code pkcs8Key} property
   */
  public PrivateKey getPkcs8Key() {
    return this.pkcs8Key;
  }

  /**
   * Assigns the {@code pkcs8Key} property.
   *
   * @param pkcs8Key the {@code pkcs8Key} property
   */
  public void setPkcs8Key(final PrivateKey pkcs8Key) {
    this.pkcs8Key = pkcs8Key;
  }

  /**
   * Gets the {@code opensslKey} property.
   *
   * @return the {@code opensslKey} property
   */
  public PrivateKey getOpensslKey() {
    return this.opensslKey;
  }

  /**
   * Assigns the {@code opensslKey} property.
   *
   * @param opensslKey the {@code opensslKey} property
   */
  public void setOpensslKey(final PrivateKey opensslKey) {
    this.opensslKey = opensslKey;
  }

  /**
   * Gets the {@code cert} property.
   *
   * @return the {@code cert} property
   */
  public X509Certificate getCert() {
    return this.cert;
  }

  /**
   * Assigns the {@code cert} property.
   *
   * @param cert the {@code cert} property
   */
  public void setCert(final X509Certificate cert) {
    this.cert = cert;
  }

  /**
   * Gets the {@code publicKey} property.
   *
   * @return the {@code publicKey} property
   */
  public PublicKey getPublicKey() {
    return this.publicKey;
  }

  /**
   * Assigns the {@code publicKey} property.
   *
   * @param publicKey the {@code publicKey} property
   */
  public void setPublicKey(final PublicKey publicKey) {
    this.publicKey = publicKey;
  }

  /**
   * Gets the {@code publicKey2} property.
   *
   * @return the {@code publicKey2} property
   */
  public PublicKey getPublicKey2() {
    return this.publicKey2;
  }

  /**
   * Assigns the {@code publicKey2} property.
   *
   * @param publicKey2 the {@code publicKey2} property
   */
  public void setPublicKey2(final PublicKey publicKey2) {
    this.publicKey2 = publicKey2;
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
    final ConvertersConfigurationProperties that = (ConvertersConfigurationProperties) o;
    return Objects.equals(this.pkcs8Key, that.pkcs8Key) && Objects.equals(this.opensslKey, that.opensslKey)
        && Objects.equals(this.cert, that.cert) && Objects.equals(this.publicKey, that.publicKey)
        && Objects.equals(this.publicKey2, that.publicKey2);
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hash(this.pkcs8Key, this.opensslKey, this.cert, this.publicKey, this.publicKey2);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return "ConvertersConfigurationProperties(pkcs8Key=" + this.pkcs8Key + ", opensslKey=" + this.opensslKey
        + ", cert=" + this.cert + ", publicKey=" + this.publicKey + ", publicKey2=" + this.publicKey2 + ")";
  }

}
