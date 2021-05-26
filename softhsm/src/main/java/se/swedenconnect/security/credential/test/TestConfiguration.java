/*
 * Copyright 2020-2021 Sweden Connect
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

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import lombok.Setter;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.Pkcs11Credential;
import se.swedenconnect.security.credential.PkiCredential;
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

  @Configuration
  @Profile("!softhsm")
  @ConfigurationProperties("test.credential")
  public static class DefaultConfiguration {

    @Setter
    private BasicCredential rsa1;

    @Bean("rsa1")
    public PkiCredential rsa1() {
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
    public PkiCredential rsa1() {
      return this.rsa1;
    }
  }

  @Bean("rsa1_OpenSaml")
  public OpenSamlCredential rsa1OpenSaml(@Qualifier("rsa1") final PkiCredential credential) {
    return new OpenSamlCredential(credential);
  }

  @Bean("rsa1b")
  @ConfigurationProperties("test.credential.rsa1b")
  public PkiCredential rsa1b() {
    return new KeyStoreCredential();
  }

//  @Bean("rsa1bb")
//  @ConfigurationProperties("test.credential.rsa1bb")
//  public PkiCredential rsa1bb(final KeyStore keyStore) {
//    KeyStoreCredential cred = new KeyStoreCredential();
//    cred.setKeyStore(keyStore);
//    return cred;
//  }

  @Bean("keyStore")
  @ConfigurationProperties("test.keystore")
  public KeyStoreFactoryBean keyStore() {
    return new KeyStoreFactoryBean();
  }

}
