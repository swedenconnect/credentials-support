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
package se.swedenconnect.security.credential.spring;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.spring.config.KeyStoreReference;
import se.swedenconnect.security.credential.spring.config.PkiCredentialReference;

import java.security.KeyStore;

/**
 * @author Martin Lindström
 */
@ConfigurationProperties("test")
public class TestConfigurationProperties {

  /**
   * Object 1.
   */
  @Getter
  @Setter
  private TestObjectProperties object1;

  public static class TestObjectProperties {

    /**
     * Key store.
     */
    @Setter
    @Getter
    private KeyStoreReference keyStore;

    /**
     * Credential.
     */
    @Setter
    @Getter
    private PkiCredentialReference credential;

    @PostConstruct
    public void init() {
      if (this.keyStore != null) {
        final KeyStore ks = this.keyStore.get();
        if (ks == null) {
          throw new RuntimeException("error");
        }
      }
      if (this.credential != null) {
        final PkiCredential cred = this.credential.get();
        if (cred == null) {
          throw new RuntimeException("error");
        }
      }
    }
  }
}
