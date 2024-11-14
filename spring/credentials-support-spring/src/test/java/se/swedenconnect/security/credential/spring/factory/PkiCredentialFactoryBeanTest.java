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
package se.swedenconnect.security.credential.spring.factory;

import org.junit.jupiter.api.Test;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.config.properties.PemCredentialConfigurationProperties;
import se.swedenconnect.security.credential.config.properties.PkiCredentialConfigurationProperties;
import se.swedenconnect.security.credential.config.properties.StoreConfigurationProperties;
import se.swedenconnect.security.credential.config.properties.StoreCredentialConfigurationProperties;
import se.swedenconnect.security.credential.factory.KeyStoreFactory;

import java.security.KeyStore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test cases for PkiCredentialFactoryBean.
 *
 * @author Martin Lindström
 */
class PkiCredentialFactoryBeanTest {

  @Test
  void testPem() throws Exception {
    final PemCredentialConfigurationProperties properties = new PemCredentialConfigurationProperties();
    properties.setName("test");
    properties.setCertificates("rsa1.crt");
    properties.setPrivateKey("rsa1.pkcs8.key");

    final PkiCredentialFactoryBean factory = new PkiCredentialFactoryBean(properties);
    factory.afterPropertiesSet();

    assertEquals(PkiCredential.class, factory.getObjectType());

    final PkiCredential credential = factory.getObject();
    assertNotNull(credential);
    assertEquals("test", credential.getName());
    assertEquals(1, credential.getCertificateChain().size());

    final PkiCredentialConfigurationProperties cp = new PkiCredentialConfigurationProperties();
    cp.setPem(properties);

    final PkiCredentialFactoryBean factory2 = new PkiCredentialFactoryBean(properties);
    factory2.afterPropertiesSet();

    final PkiCredential credential2 = factory2.getObject();
    assertNotNull(credential2);
    assertEquals("test", credential2.getName());
    assertEquals(1, credential2.getCertificateChain().size());
  }

  @Test
  void testStore() throws Exception {
    final StoreCredentialConfigurationProperties properties = new StoreCredentialConfigurationProperties();
    properties.setName("test");
    properties.setStore(new StoreConfigurationProperties());
    properties.getStore().setLocation("rsa1.jks");
    properties.getStore().setPassword("secret");
    properties.setKey(new StoreCredentialConfigurationProperties.KeyConfigurationProperties());
    properties.getKey().setAlias("test");
    // Leave out the key password - the keystore password will be used then ...

    final PkiCredentialFactoryBean factory = new PkiCredentialFactoryBean(properties);
    factory.afterPropertiesSet();

    final PkiCredential credential = factory.getObject();
    assertNotNull(credential);
    assertEquals("test", credential.getName());
    assertEquals(1, credential.getCertificateChain().size());
  }

  @Test
  void testStoreWithReference() throws Exception {

    final StoreConfigurationProperties storeProperties = new StoreConfigurationProperties();
    storeProperties.setLocation("rsa1.jks");
    storeProperties.setPassword("secret");
    final KeyStore keyStore = KeyStoreFactory.loadKeyStore(storeProperties, null);

    final StoreCredentialConfigurationProperties properties = new StoreCredentialConfigurationProperties();
    properties.setName("test");
    properties.setStoreReference("the-store");
    properties.setKey(new StoreCredentialConfigurationProperties.KeyConfigurationProperties());
    properties.getKey().setAlias("test");
    properties.getKey().setKeyPassword("secret");

    final PkiCredentialFactoryBean factory = new PkiCredentialFactoryBean(properties);
    factory.setKeyStoreSupplier(r -> keyStore);
    factory.setKeyStoreReloaderSupplier(s -> null);
    factory.afterPropertiesSet();

    final PkiCredential credential = factory.getObject();
    assertNotNull(credential);
    assertEquals("test", credential.getName());
    assertEquals(1, credential.getCertificateChain().size());
  }

  @Test
  void testBadPkiCredentialConfiguration() {
    final PkiCredentialConfigurationProperties properties = new PkiCredentialConfigurationProperties();
    properties.setPem(new PemCredentialConfigurationProperties());
    properties.setJks(new StoreCredentialConfigurationProperties());

    final PkiCredentialFactoryBean factory = new PkiCredentialFactoryBean(properties);
    assertThrows(IllegalArgumentException.class, factory::afterPropertiesSet);

    final PkiCredentialConfigurationProperties properties2 = new PkiCredentialConfigurationProperties();
    final PkiCredentialFactoryBean factory2 = new PkiCredentialFactoryBean(properties2);
    assertThrows(IllegalArgumentException.class, factory2::afterPropertiesSet);
  }

}
