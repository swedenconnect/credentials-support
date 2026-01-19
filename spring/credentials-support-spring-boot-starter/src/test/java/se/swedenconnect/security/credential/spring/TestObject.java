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

import lombok.Getter;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.spring.config.KeyStoreReference;
import se.swedenconnect.security.credential.spring.config.PkiCredentialReference;

import java.security.KeyStore;
import java.util.Optional;

/**
 * For testing.
 *
 * @author Martin Lindström
 */
public class TestObject {

  @Getter
  private final KeyStore keyStore;

  @Getter
  private final PkiCredential credential;

  public TestObject(final TestConfigurationProperties.TestObjectProperties properties) {
    this.keyStore = Optional.ofNullable(properties.getKeyStore()).map(KeyStoreReference::get).orElse(null);
    this.credential = Optional.ofNullable(properties.getCredential()).map(PkiCredentialReference::get).orElse(null);
  }

}
