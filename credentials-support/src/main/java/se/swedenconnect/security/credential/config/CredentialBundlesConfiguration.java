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
package se.swedenconnect.security.credential.config;

import jakarta.annotation.Nonnull;

import java.util.Map;
import java.util.Optional;

/**
 * Configuration interface for bundles of credentials and key stores.
 * <p>
 * Note: If both PEM configuration and JKS (Java Key Store) is used, the ID:s used must be unique for all credentials
 * (i.e., both those configured using PEM-format and those configured using key store formats).
 * </p>
 *
 * @author Martin Lindström
 */
public interface CredentialBundlesConfiguration {

  /**
   * Gets the map of key store ID:s and key store configurations.
   *
   * @return a map of key store ID:s and key store configurations
   */
  Optional<Map<String, StoreConfiguration>> keystore();

  /**
   * Gets the map of credential ID:s and PEM based credential configurations.
   *
   * @return a map of credential ID:s and PEM-based credential configurations
   */
  Optional<Map<String, PemCredentialConfiguration>> pem();

  /**
   * Gets the map of credential ID:s and key store based credential configurations.
   *
   * @return a map of credential ID:s and key store based credential configurations
   */
  Optional<Map<String, StoreCredentialConfiguration>> jks();

}
