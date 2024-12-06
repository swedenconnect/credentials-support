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

import jakarta.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.bundle.CredentialBundles;
import se.swedenconnect.security.credential.bundle.NoSuchCredentialException;
import se.swedenconnect.security.credential.bundle.NoSuchKeyStoreException;
import se.swedenconnect.security.credential.config.properties.PemCredentialConfigurationProperties;
import se.swedenconnect.security.credential.config.properties.PkiCredentialConfigurationProperties;
import se.swedenconnect.security.credential.config.properties.StoreConfigurationProperties;
import se.swedenconnect.security.credential.config.properties.StoreCredentialConfigurationProperties;
import se.swedenconnect.security.credential.factory.KeyStoreFactory;

import java.security.KeyStore;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

    final PkiCredentialFactoryBean factory2 = new PkiCredentialFactoryBean(cp);
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
    factory.setKeyStoreProvider(r -> keyStore);
    factory.setKeyStoreReloaderProvider(s -> null);
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

  @Test
  void testCredentialReference() throws Exception {
    final PemCredentialConfigurationProperties _properties = new PemCredentialConfigurationProperties();
    _properties.setName("test");
    _properties.setCertificates("rsa1.crt");
    _properties.setPrivateKey("rsa1.pkcs8.key");

    final PkiCredentialFactoryBean _factory = new PkiCredentialFactoryBean(_properties);
    _factory.afterPropertiesSet();

    final PkiCredential credential = _factory.getObject();

    final PkiCredentialConfigurationProperties properties = new PkiCredentialConfigurationProperties();
    properties.setBundle("ref");

    final PkiCredentialFactoryBean factory = new PkiCredentialFactoryBean(properties);
    final IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, factory::afterPropertiesSet);
    assertEquals("credentialProvider or credentialBundles must be supplied", ex.getMessage());

    factory.setCredentialProvider(id -> credential);
    factory.afterPropertiesSet();

    final PkiCredential credential2 = factory.getObject();
    assertTrue(credential2 == credential);

  }

  @Test
  void testCredentialReferenceWithBundles() throws Exception {
    final PemCredentialConfigurationProperties _properties = new PemCredentialConfigurationProperties();
    _properties.setName("test");
    _properties.setCertificates("rsa1.crt");
    _properties.setPrivateKey("rsa1.pkcs8.key");

    final PkiCredentialFactoryBean _factory = new PkiCredentialFactoryBean(_properties);
    _factory.afterPropertiesSet();

    final PkiCredential credential = _factory.getObject();

    final PkiCredentialFactoryBean factory = new PkiCredentialFactoryBean("ref");
    factory.setCredentialBundles(new CredentialBundles() {
      @Nonnull
      @Override
      public PkiCredential getCredential(@Nonnull final String id) throws NoSuchCredentialException {
        if ("ref".equals(id)) {
          return credential;
        }
        throw new NoSuchCredentialException(id, "e");
      }

      @Nonnull
      @Override
      public List<String> getRegisteredCredentials() {
        return List.of(credential.getName());
      }

      @Nonnull
      @Override
      public KeyStore getKeyStore(@Nonnull final String id) throws NoSuchKeyStoreException {
        throw new NoSuchKeyStoreException(id, "e");
      }

      @Nonnull
      @Override
      public List<String> getRegisteredKeyStores() {
        return List.of();
      }
    });
    factory.afterPropertiesSet();

    final PkiCredential credential2 = factory.getObject();
    assertTrue(credential2 == credential);

  }

}
