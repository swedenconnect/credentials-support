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
import se.swedenconnect.security.credential.config.CredentialBundlesConfiguration;
import se.swedenconnect.security.credential.config.PemCredentialConfiguration;
import se.swedenconnect.security.credential.config.StoreConfiguration;
import se.swedenconnect.security.credential.config.StoreCredentialConfiguration;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Configuration properties for bundles of credentials and key stores.
 * <p>
 * Note: If both PEM configuration and JKS (Java Key Store) is used, the ID:s used must be unique for all credentials
 * (i.e., both those configured using PEM-format and those configured using key store formats).
 * </p>
 *
 * @author Martin Lindström
 */
public class CredentialBundlesConfigurationProperties implements CredentialBundlesConfiguration {

  /**
   * Map of key store ID:s and key store configurations.
   */
  private Map<String, StoreConfigurationProperties> keystore;

  /**
   * Map of credential ID:s and PEM based credential configurations.
   */
  private Map<String, PemCredentialConfigurationProperties> pem;

  /**
   * Map of credential ID:s and key store based credential configurations.
   */
  private Map<String, StoreCredentialConfigurationProperties> jks;

  /**
   * Gets the map of key store ID:s and key store configurations.
   *
   * @return a map of key store configurations
   */
  @Nullable
  public Map<String, StoreConfigurationProperties> getKeystore() {
    return this.keystore;
  }

  /**
   * Assigns the map of key store ID:s and key store configurations.
   *
   * @param keystore a map of key store configurations
   */
  public void setKeystore(@Nullable final Map<String, StoreConfigurationProperties> keystore) {
    this.keystore = keystore;
  }

  /**
   * Gets the map of credential ID:s and PEM based credential configurations.
   *
   * @return a map of PEM based credential configurations
   */
  @Nullable
  public Map<String, PemCredentialConfigurationProperties> getPem() {
    return this.pem;
  }

  /**
   * Assigns the map of credential ID:s and PEM based credential configurations.
   *
   * @param pem a map of PEM based credential configurations
   */
  public void setPem(@Nullable final Map<String, PemCredentialConfigurationProperties> pem) {
    this.pem = pem;
  }

  /**
   * Gets the map of credential ID:s and key store based credential configurations.
   *
   * @return a map of key store based credential configurations
   */
  @Nullable
  public Map<String, StoreCredentialConfigurationProperties> getJks() {
    return this.jks;
  }

  /**
   * Assigns the map of credential ID:s and key store based credential configurations.
   *
   * @param jks a map of key store based credential configurations
   */
  public void setJks(@Nullable final Map<String, StoreCredentialConfigurationProperties> jks) {
    this.jks = jks;
  }

  /** {@inheritDoc} */
  @Override
  public Optional<Map<String, StoreConfiguration>> keystore() {
    return Optional.ofNullable(this.getKeystore())
        .map(ks -> ks.entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue)));
  }

  /** {@inheritDoc} */
  @Override
  public Optional<Map<String, PemCredentialConfiguration>> pem() {
    return Optional.ofNullable(this.getPem())
        .map(pem -> pem.entrySet().stream()
            .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue)));
  }

  /** {@inheritDoc} */
  @Override
  public Optional<Map<String, StoreCredentialConfiguration>> jks() {
    return Optional.ofNullable(this.getJks())
        .map(jks -> jks.entrySet().stream()
            .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue)));
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
    final CredentialBundlesConfigurationProperties that = (CredentialBundlesConfigurationProperties) o;
    return Objects.equals(this.keystore, that.keystore) && Objects.equals(this.pem, that.pem)
        && Objects.equals(this.jks, that.jks);
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hash(this.keystore, this.pem, this.jks);
  }

}
