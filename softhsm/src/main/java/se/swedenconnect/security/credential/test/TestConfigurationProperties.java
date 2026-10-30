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
package se.swedenconnect.security.credential.test;

import jakarta.annotation.PostConstruct;
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
  private KeyStoreReference keystore;

  /**
   * Reference to the RSA1 credential.
   */
  private PkiCredentialReference rsa1;

  /**
   * Reference to the RSA1B credential.
   */
  private PkiCredentialReference rsa1b;

  /**
   * Configuration for the RSA2 credential. This one does not use references, but instead configures the
   * credential in-place.
   */
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

  /**
   * Gets the reference to the test key store.
   *
   * @return the key store reference
   */
  public KeyStoreReference getKeystore() {
    return this.keystore;
  }

  /**
   * Assigns the reference to the test key store.
   *
   * @param keystore the key store reference
   */
  public void setKeystore(final KeyStoreReference keystore) {
    this.keystore = keystore;
  }

  /**
   * Gets the reference to the RSA1 credential.
   *
   * @return the credential reference
   */
  public PkiCredentialReference getRsa1() {
    return this.rsa1;
  }

  /**
   * Assigns the reference to the RSA1 credential.
   *
   * @param rsa1 the credential reference
   */
  public void setRsa1(final PkiCredentialReference rsa1) {
    this.rsa1 = rsa1;
  }

  /**
   * Gets the reference to the RSA1B credential.
   *
   * @return the credential reference
   */
  public PkiCredentialReference getRsa1b() {
    return this.rsa1b;
  }

  /**
   * Assigns the reference to the RSA1B credential.
   *
   * @param rsa1b the credential reference
   */
  public void setRsa1b(final PkiCredentialReference rsa1b) {
    this.rsa1b = rsa1b;
  }

  /**
   * Gets the configuration for the RSA2 credential.
   *
   * @return the credential configuration
   */
  public PkiCredentialConfigurationProperties getRsa2() {
    return this.rsa2;
  }

  /**
   * Assigns the configuration for the RSA2 credential.
   *
   * @param rsa2 the credential configuration
   */
  public void setRsa2(final PkiCredentialConfigurationProperties rsa2) {
    this.rsa2 = rsa2;
  }
}
