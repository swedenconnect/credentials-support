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

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.bundle.CredentialBundles;
import se.swedenconnect.security.credential.config.ConfigurationResourceLoader;
import se.swedenconnect.security.credential.factory.PkiCredentialFactory;
import se.swedenconnect.security.credential.opensaml.OpenSamlCredential;

import java.security.KeyStore;

/**
 * Configuration of credentials ...
 *
 * @author Martin Lindström (martin@idsec.se)
 */
@Configuration
@EnableConfigurationProperties(TestConfigurationProperties.class)
public class TestConfiguration {

  private final TestConfigurationProperties properties;
  private final ConfigurationResourceLoader resourceLoader;
  private final CredentialBundles credentialBundles;

  public TestConfiguration(final TestConfigurationProperties properties,
      final ConfigurationResourceLoader resourceLoader, final CredentialBundles credentialBundles) {
    this.properties = properties;
    this.resourceLoader = resourceLoader;
    this.credentialBundles = credentialBundles;
  }

  @Bean("rsa1")
  PkiCredential rsa1() {
    return this.properties.getRsa1().get();
  }

  @Bean("rsa1_OpenSaml")
  OpenSamlCredential rsa1OpenSaml(@Qualifier(value = "rsa1") final PkiCredential credential) {
    return new OpenSamlCredential(credential);
  }

  @Bean("rsa1b")
  PkiCredential rsa1b() {
    return this.properties.getRsa1b().get();
  }

  @Bean("rsa2")
  PkiCredential rsa2() throws Exception {
    return PkiCredentialFactory.createCredential(this.properties.getRsa2(), this.resourceLoader, null,
        this.credentialBundles::getKeyStore, null);
  }

  @Bean("keyStore")
  KeyStore keyStore() {
    return this.properties.getKeystore().get();
  }

}
