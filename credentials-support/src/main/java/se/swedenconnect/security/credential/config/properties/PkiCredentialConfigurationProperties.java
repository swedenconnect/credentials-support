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
import se.swedenconnect.security.credential.config.PemCredentialConfiguration;
import se.swedenconnect.security.credential.config.PkiCredentialConfiguration;
import se.swedenconnect.security.credential.config.StoreCredentialConfiguration;

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
  @Getter
  @Setter
  private String bundle;

  /**
   * Configuration for a JKS (Java KeyStore) based credential.
   */
  @Getter
  @Setter
  @org.springframework.boot.context.properties.NestedConfigurationProperty
  private StoreCredentialConfigurationProperties jks;

  /**
   * Configuration for a PEM-based credential.
   */
  @Getter
  @Setter
  @org.springframework.boot.context.properties.NestedConfigurationProperty
  private PemCredentialConfigurationProperties pem;

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
}
