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
package se.swedenconnect.security.credential.config;

import java.util.Optional;

/**
 * Configuration interface for configuring a stand-alone
 * {@link se.swedenconnect.security.credential.PkiCredential PkiCredential}.
 * <p>
 * Note: One, and exactly one, of {@link #bundle()}, {@link #jks()} or {@link #pem()} must be supplied.
 * </p>
 *
 * @author Martin Lindström
 */
public interface PkiCredentialConfiguration {

  /**
   * Pointer to a {@link se.swedenconnect.security.credential.PkiCredential PkiCredential} accessible via the
   * {@link se.swedenconnect.security.credential.bundle.CredentialBundles CredentialBundles} bean/interface.
   *
   * @return bundle name
   */
  Optional<String> bundle();

  /**
   * Configuration for a JKS (Java KeyStore) based credential.
   *
   * @return configuration for a JKS (Javc KeyStore) based credential
   */
  Optional<StoreCredentialConfiguration> jks();

  /**
   * Configuration for a PEM-based credential.
   *
   * @return configuration for a PEM-based credential
   */
  Optional<PemCredentialConfiguration> pem();

}
