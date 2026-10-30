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
package se.swedenconnect.security.credential.spring;

import jakarta.annotation.PostConstruct;
import org.springframework.boot.context.properties.ConfigurationProperties;
import se.swedenconnect.security.credential.spring.config.KeyStoreReference;
import se.swedenconnect.security.credential.spring.config.PkiCredentialReference;

import java.util.Optional;

/**
 * @author Martin Lindström
 */
@ConfigurationProperties("test")
public class TestConfigurationProperties {

  /**
   * Object 1.
   */
  private TestObjectProperties object1;

  /**
   * Object 3b.
   */
  private TestObjectProperties object3b;

  public static class TestObjectProperties {

    /**
     * Key store.
     */
    private KeyStoreReference keyStore;

    /**
     * Credential.
     */
    private PkiCredentialReference credential;

    @PostConstruct
    public void init() {
      if (this.keyStore != null) {
        Optional.ofNullable(this.keyStore.get()).orElseThrow(() -> new RuntimeException("Keystore not set"));
      }
      if (this.credential != null) {
        Optional.ofNullable(this.credential.get()).orElseThrow(() -> new RuntimeException("Credential not set"));
      }
    }

    /**
     * Gets the key store.
     *
     * @return the key store
     */
    public KeyStoreReference getKeyStore() {
      return this.keyStore;
    }

    /**
     * Assigns the key store.
     *
     * @param keyStore the key store
     */
    public void setKeyStore(final KeyStoreReference keyStore) {
      this.keyStore = keyStore;
    }

    /**
     * Gets the credential.
     *
     * @return the credential
     */
    public PkiCredentialReference getCredential() {
      return this.credential;
    }

    /**
     * Assigns the credential.
     *
     * @param credential the credential
     */
    public void setCredential(final PkiCredentialReference credential) {
      this.credential = credential;
    }

  }

  /**
   * Gets the object 1.
   *
   * @return the object 1
   */
  public TestObjectProperties getObject1() {
    return this.object1;
  }

  /**
   * Assigns the object 1.
   *
   * @param object1 the object 1
   */
  public void setObject1(final TestObjectProperties object1) {
    this.object1 = object1;
  }

  /**
   * Gets the object 3b.
   *
   * @return the object 3b
   */
  public TestObjectProperties getObject3b() {
    return this.object3b;
  }

  /**
   * Assigns the object 3b.
   *
   * @param object3b the object 3b
   */
  public void setObject3b(final TestObjectProperties object3b) {
    this.object3b = object3b;
  }

}
