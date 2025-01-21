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
package se.swedenconnect.security.credential.config.properties;

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.security.credential.config.CredentialBundlesConfiguration;
import se.swedenconnect.security.credential.config.PemCredentialConfiguration;
import se.swedenconnect.security.credential.config.StoreConfiguration;
import se.swedenconnect.security.credential.config.StoreCredentialConfiguration;

import java.util.Map;
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
  @Getter
  @Setter
  private Map<String, StoreConfigurationProperties> keystore;

  /**
   * Map of credential ID:s and PEM based credential configurations.
   */
  @Getter
  @Setter
  private Map<String, PemCredentialConfigurationProperties> pem;

  /**
   * Map of credential ID:s and key store based credential configurations.
   */
  @Getter
  @Setter
  private Map<String, StoreCredentialConfigurationProperties> jks;

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

}
