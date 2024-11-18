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
package se.swedenconnect.security.credential.factory;

import jakarta.annotation.Nonnull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.bundle.CredentialBundles;
import se.swedenconnect.security.credential.bundle.NoSuchCredentialException;
import se.swedenconnect.security.credential.bundle.NoSuchKeyStoreException;
import se.swedenconnect.security.credential.pkcs11.MockSunPkcs11Provider;

import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test cases for PkiCredentialFactoryBean.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
class PkiCredentialFactoryBeanTest {

  private final static char[] PW = "secret".toCharArray();

  @BeforeEach
  public void init() {
    Security.addProvider(new MockSunPkcs11Provider());

    // We let rsa1.jks simulate our PKCS#11 device
    MockSunPkcs11Provider.MockedPkcs11ResourceHolder.getInstance()
        .setResource(new org.cryptacular.io.ClassPathResource("rsa1.jks"));
  }

  @AfterEach
  public void after() {
    Security.removeProvider(MockSunPkcs11Provider.PROVIDER_BASE_NAME);

    final Provider[] providers = Security.getProviders();
    for (final Provider p : providers) {
      if (p.getName().contains(MockSunPkcs11Provider.PROVIDER_BASE_NAME)) {
        Security.removeProvider(p.getName());
      }
    }

    MockSunPkcs11Provider.MockedPkcs11ResourceHolder.getInstance().setResource(null);
    MockSunPkcs11Provider.MockedPkcs11ResourceHolder.getInstance().setMockNoCertificate(false);
  }

  @Test
  void testObjectType() {
    final PkiCredentialFactoryBean factory = new PkiCredentialFactoryBean();
    assertEquals(PkiCredential.class, factory.getObjectType());
  }

  @Test
  void testMissingConfiguration1() {
    assertThrows(IllegalArgumentException.class, () -> {
      final PkiCredentialFactoryBean factory = new PkiCredentialFactoryBean();
      factory.setCertificate(new ClassPathResource("rsa1.crt"));
      factory.afterPropertiesSet();
    });
  }

  @Test
  void testMissingConfiguration2() {
    assertThrows(SecurityException.class, () -> {
      final PkiCredentialFactoryBean factory = new PkiCredentialFactoryBean();
      factory.setCertificate(new ClassPathResource("rsa1.crt"));
      factory.setSingleton(false);
      factory.getObject();
    });
  }

  @Test
  void testBasicCredential() throws Exception {
    final PkiCredentialFactoryBean factory = new PkiCredentialFactoryBean();
    factory.setCertificate(new ClassPathResource("rsa1.crt"));
    factory.setPrivateKey(new ClassPathResource("rsa1.pkcs8.key"));
    factory.setName("test");
    factory.afterPropertiesSet();
    final PkiCredential credential = factory.getObject();
    assertTrue(credential instanceof BasicCredential);
    assertEquals("test", credential.getName());
    factory.destroy();
  }

  @Test
  void testKeyStoreCredential() throws Exception {
    PkiCredentialFactoryBean factory = new PkiCredentialFactoryBean();
    factory.setResource(new ClassPathResource("rsa1.jks"));
    factory.setPassword(PW);
    factory.setAlias("test");
    factory.afterPropertiesSet();
    PkiCredential credential = factory.getObject();
    assertTrue(credential instanceof KeyStoreCredential);
    factory.destroy();

    factory = new PkiCredentialFactoryBean();
    factory.setResource(new ClassPathResource("rsa1.jks"));
    factory.setPassword(PW);
    factory.setAlias("test");
    factory.setKeyPassword(PW);
    factory.setType("JKS");
    factory.setProvider("SUN");
    factory.afterPropertiesSet();
    credential = factory.getObject();
    assertTrue(credential instanceof KeyStoreCredential);
    factory.destroy();
  }

  @Test
  void testPkiCredentialConfigurationProperties() throws Exception {
    final PkiCredentialConfigurationProperties props = new PkiCredentialConfigurationProperties();
    props.setCertificate(new ClassPathResource("rsa1.crt"));
    props.setPrivateKey(new ClassPathResource("rsa1.pkcs8.key"));
    props.setName("name");

    final PkiCredentialFactoryBean factory = new PkiCredentialFactoryBean(props, null);
    factory.afterPropertiesSet();
    final PkiCredential credential = factory.getObject();
    assertTrue(credential instanceof BasicCredential);
    factory.destroy();
  }

  @Test
  void testBundles() throws Exception {
    final PkiCredentialConfigurationProperties props = new PkiCredentialConfigurationProperties();
    props.setCertificate(new ClassPathResource("rsa1.crt"));
    props.setPrivateKey(new ClassPathResource("rsa1.pkcs8.key"));
    props.setName("name");

    final PkiCredentialFactoryBean _factory = new PkiCredentialFactoryBean(props, null);
    _factory.afterPropertiesSet();
    final PkiCredential credential = _factory.getObject();

    final PkiCredentialFactoryBean factory1 = new PkiCredentialFactoryBean();
    factory1.setBundle("ref");
    assertThrows(IllegalArgumentException.class, factory1::afterPropertiesSet);

    final CredentialBundles credentialBundles = new CredentialBundles() {
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
    };

    final PkiCredentialFactoryBean factory2 = new PkiCredentialFactoryBean(credentialBundles);
    factory2.setBundle("ref");
    factory2.afterPropertiesSet();

    final PkiCredential credential2 = factory2.getObject();
    assertTrue(credential2 == credential);

    // Test with properties
    final PkiCredentialConfigurationProperties props3 = new PkiCredentialConfigurationProperties();
    props3.setBundle("ref");

    final PkiCredentialFactoryBean factory3 = new PkiCredentialFactoryBean(props3, credentialBundles);
    factory3.afterPropertiesSet();

    final PkiCredential credential3 = factory3.getObject();
    assertTrue(credential3 == credential);

  }

}
