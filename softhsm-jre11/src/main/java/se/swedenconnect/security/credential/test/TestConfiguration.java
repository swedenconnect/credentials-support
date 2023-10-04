/*
 * Copyright 2020-2023 Sweden Connect
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

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import lombok.Setter;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.Pkcs11Credential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.converters.PropertyToPrivateKeyConverter;
import se.swedenconnect.security.credential.converters.PropertyToX509CertificateConverter;
import se.swedenconnect.security.credential.factory.KeyStoreFactoryBean;
import se.swedenconnect.security.credential.opensaml.OpenSamlCredential;

/**
 * Configuration of credentials ...
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Configuration
public class TestConfiguration {

  /**
   * Gets the {@link PropertyToX509CertificateConverter} that enables us to point to a certificate on file from a
   * properties file and get a {@link X509Certificate} injected.
   *
   * @return the PropertyToX509CertificateConverter bean
   */
  @Bean
  @ConfigurationPropertiesBinding
  PropertyToX509CertificateConverter propertyToX509CertificateConverter() {
    return new PropertyToX509CertificateConverter();
  }

  /**
   * Gets the {@link PropertyToPrivateKeyConverter} that enables us to point to a (non-encrypted) private key of file
   * from a properties file and get a {@link PrivateKey} injected.
   *
   * @return a PropertyToPrivateKeyConverter bean
   */
  @Bean
  @ConfigurationPropertiesBinding
  PropertyToPrivateKeyConverter propertyToPrivateKeyConverter() {
    return new PropertyToPrivateKeyConverter();
  }

  @Configuration
  @Profile("!softhsm")
  @ConfigurationProperties("test.credential")
  public static class DefaultConfiguration {

    @Setter
    private BasicCredential rsa1;

    @Bean("rsa1")
    PkiCredential rsa1() {
      return this.rsa1;
    }
  }

  @Configuration
  @Profile("softhsm")
  @ConfigurationProperties("test.credential")
  public static class Pkcs11Configuration {

    @Setter
    private Pkcs11Credential rsa1;

    @Bean("rsa1")
    PkiCredential rsa1() {
      return this.rsa1;
    }
  }

  @Bean("rsa1_OpenSaml")
  OpenSamlCredential rsa1OpenSaml(@Qualifier("rsa1") final PkiCredential credential) {
    return new OpenSamlCredential(credential);
  }

  @Bean("rsa1b")
  @ConfigurationProperties("test.credential.rsa1b")
  PkiCredential rsa1b() {
    return new KeyStoreCredential();
  }

  @Bean("rsa1bb")
  @ConfigurationProperties("test.credential.rsa1bb")
  PkiCredential rsa1bb(final KeyStore keyStore) {
    KeyStoreCredential cred = new KeyStoreCredential();
    cred.setKeyStore(keyStore);
    return cred;
  }

  @Bean("keyStore")
  @ConfigurationProperties("test.keystore")
  KeyStoreFactoryBean keyStore() {
    return new KeyStoreFactoryBean();
  }

}
