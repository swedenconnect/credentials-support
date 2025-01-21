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
package se.swedenconnect.security.credential.test;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import se.swedenconnect.security.credential.config.properties.PkiCredentialConfigurationProperties;
import se.swedenconnect.security.credential.spring.config.KeyStoreReference;
import se.swedenconnect.security.credential.spring.config.PkiCredentialReference;

import java.util.Optional;

/**
 * Illustrates how Spring Configuration Properties can be set up to inject credentials and key stores.
 *
 * @author Martin Lindström
 */
@ConfigurationProperties("test")
public class TestConfigurationProperties {

  /**
   * Reference to the test key store.
   */
  @Getter
  @Setter
  private KeyStoreReference keystore;

  /**
   * Reference to the RSA1 credential.
   */
  @Getter
  @Setter
  private PkiCredentialReference rsa1;

  /**
   * Reference to the RSA1B credential.
   */
  @Getter
  @Setter
  private PkiCredentialReference rsa1b;

  /**
   * Configuration for the RSA2 credential. This one does not use references, but instead configures the
   * credential in-place.
   */
  @Getter
  @Setter
  @NestedConfigurationProperty
  private PkiCredentialConfigurationProperties rsa2;

  /**
   * Resolve all reference to make sure that they can be resolved against the
   * {@link se.swedenconnect.security.credential.bundle.CredentialBundles CredentialBundles} bean.
   *
   * @throws Exception for resolve errors
   */
  @PostConstruct
  public void init() throws Exception {
    Optional.ofNullable(this.keystore).ifPresent(KeyStoreReference::get);
    Optional.ofNullable(this.rsa1).ifPresent(PkiCredentialReference::get);
    Optional.ofNullable(this.rsa1b).ifPresent(PkiCredentialReference::get);
  }
}
