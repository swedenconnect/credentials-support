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
import se.swedenconnect.security.credential.config.PkiCredentialConfiguration;
import se.swedenconnect.security.credential.config.StoreCredentialConfiguration;

import java.util.Objects;
import java.util.Optional;

/**
 * Configuration properties for configuring a stand-alone
 * {@link se.swedenconnect.security.credential.PkiCredential PkiCredential}.
 * <p>
 * Note: One, and exactly one, of {@link #bundle()}, {@link #jks()} or {@link #pem()} must be supplied.
 * </p>
 *
 * @author Martin Lindström
 */
public class PkiCredentialConfigurationProperties implements PkiCredentialConfiguration {

  /**
   * Pointer to a PkiCredential accessible via the CredentialBundles bean.
   */
  private String bundle;

  /**
   * Configuration for a JKS (Java KeyStore) based credential.
   */
  @org.springframework.boot.context.properties.NestedConfigurationProperty
  private StoreCredentialConfigurationProperties jks;

  /**
   * Configuration for a PEM-based credential.
   */
  @org.springframework.boot.context.properties.NestedConfigurationProperty
  private PemCredentialConfigurationProperties pem;

  /**
   * Gets the pointer to a PkiCredential accessible via the CredentialBundles bean.
   *
   * @return the bundle reference
   */
  @Nullable
  public String getBundle() {
    return this.bundle;
  }

  /**
   * Assigns the pointer to a PkiCredential accessible via the CredentialBundles bean.
   *
   * @param bundle the bundle reference
   */
  public void setBundle(@Nullable final String bundle) {
    this.bundle = bundle;
  }

  /**
   * Gets the configuration for a JKS (Java KeyStore) based credential.
   *
   * @return the JKS credential configuration
   */
  @Nullable
  public StoreCredentialConfigurationProperties getJks() {
    return this.jks;
  }

  /**
   * Assigns the configuration for a JKS (Java KeyStore) based credential.
   *
   * @param jks the JKS credential configuration
   */
  public void setJks(@Nullable final StoreCredentialConfigurationProperties jks) {
    this.jks = jks;
  }

  /**
   * Gets the configuration for a PEM-based credential.
   *
   * @return the PEM credential configuration
   */
  @Nullable
  public PemCredentialConfigurationProperties getPem() {
    return this.pem;
  }

  /**
   * Assigns the configuration for a PEM-based credential.
   *
   * @param pem the PEM credential configuration
   */
  public void setPem(@Nullable final PemCredentialConfigurationProperties pem) {
    this.pem = pem;
  }

  /** {@inheritDoc} */
  @Override
  public Optional<String> bundle() {
    return Optional.ofNullable(this.getBundle());
  }

  /** {@inheritDoc} */
  @Override
  public Optional<StoreCredentialConfiguration> jks() {
    return Optional.ofNullable(this.getJks());
  }

  /** {@inheritDoc} */
  @Override
  public Optional<PemCredentialConfiguration> pem() {
    return Optional.ofNullable(this.getPem());
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
    final PkiCredentialConfigurationProperties that = (PkiCredentialConfigurationProperties) o;
    return Objects.equals(this.bundle, that.bundle) && Objects.equals(this.jks, that.jks)
        && Objects.equals(this.pem, that.pem);
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hash(this.bundle, this.jks, this.pem);
  }

}
