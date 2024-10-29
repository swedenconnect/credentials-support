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

import org.bouncycastle.util.Arrays;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import se.swedenconnect.security.credential.pkcs11.MockSunPkcs11Provider;

import java.security.KeyStore;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test cases for KeyStoreFactoryBean.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class KeyStoreFactoryBeanTest {

  private final static char[] PW = "secret".toCharArray();

  @BeforeEach
  public void init() {
    Security.addProvider(new MockSunPkcs11Provider());

    // We let rsa1.jks simulate our PKCS#11 device
    MockSunPkcs11Provider.MockedPkcs11ResourceHolder.getInstance().setResource(new ClassPathResource("rsa1.jks"));
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
  public void testCreateFromJks() throws Exception {
    KeyStoreFactoryBean factory = new KeyStoreFactoryBean();
    factory.setResource(new ClassPathResource("rsa1.jks"));
    factory.setPassword(PW);
    factory.setType("JKS");
    factory.setProvider("SUN");
    factory.setSingleton(false);
    factory.afterPropertiesSet();

    // Test getters
    assertEquals("rsa1.jks", factory.getResource().getFilename());
    assertArrayEquals(PW, factory.getPassword());
    assertEquals("JKS", factory.getType());
    assertEquals("SUN", factory.getProvider());

    KeyStore ks = factory.getObject();
    assertNotNull(ks);
    assertEquals(KeyStore.class, factory.getObjectType());

    // If no type is set, the default type should be used ...
    //
    factory = new KeyStoreFactoryBean();
    factory.setResource(new ClassPathResource("rsa1.jks"));
    factory.setPassword(PW);
    factory.afterPropertiesSet();

    // Test getters
    assertEquals(KeyStore.getDefaultType(), factory.getType());
    ks = factory.getObject();
    assertNotNull(ks);
    assertEquals(KeyStore.getDefaultType(), ks.getType());

    // Should work with no call to afterProperties set (if not singleton) ...
    factory = new KeyStoreFactoryBean();
    factory.setResource(new ClassPathResource("rsa1.jks"));
    factory.setPassword(PW);
    factory.setSingleton(false);

    // Test getters
    assertEquals(KeyStore.getDefaultType(), factory.getType());
    ks = factory.getObject();
    assertNotNull(ks);
    assertEquals(KeyStore.getDefaultType(), ks.getType());

    // Create with constructors ...
    factory = new KeyStoreFactoryBean(new ClassPathResource("rsa1.jks"), PW);
    factory.afterPropertiesSet();
    assertNotNull(factory.getObject());

    // If this is a singleton, the password should be cleared in afterPropertiesSet ...
    final char[] cleared = new char[PW.length];
    Arrays.fill(cleared, (char) 0);
    assertArrayEquals(cleared, factory.getPassword());

    factory = new KeyStoreFactoryBean(new ClassPathResource("rsa1.jks"), PW, "JKS");
    factory.afterPropertiesSet();
    assertNotNull(factory.getObject());
  }

  @Test
  public void testMissingParameters() {
    assertThrows(IllegalArgumentException.class, () -> {
      final KeyStoreFactoryBean factory = new KeyStoreFactoryBean();
      factory.setResource(new ClassPathResource("rsa1.jks"));
      factory.afterPropertiesSet();
    });
  }

  @Test
  public void testMissingParameters2() {
    assertThrows(IllegalArgumentException.class, () -> {
      final KeyStoreFactoryBean factory = new KeyStoreFactoryBean(new ClassPathResource("rsa1.jks"), null);
      factory.afterPropertiesSet();
    });
  }

  @Test
  public void testDestroy() throws Exception {
    KeyStoreFactoryBean factory = new KeyStoreFactoryBean(new ClassPathResource("rsa1.jks"), PW);
    factory.setSingleton(false);
    factory.afterPropertiesSet();

    factory.destroy();
    final char[] cleared = new char[PW.length];
    Arrays.fill(cleared, (char) 0);
    assertArrayEquals(cleared, factory.getPassword());

    factory = new KeyStoreFactoryBean(new ClassPathResource("rsa1.jks"), null);
    factory.setSingleton(false);
    factory.destroy();
    assertNull(factory.getPassword());
  }

  @Test
  public void testPkcs11() throws Exception {
    final String cfgFile = (new ClassPathResource("cfg1.txt")).getFile().getAbsolutePath();

    final KeyStoreFactoryBean factory = new KeyStoreFactoryBean();
    factory.setPassword(PW);
    factory.setType("PKCS11");
    factory.setProvider(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
    factory.setPkcs11Configuration(cfgFile);
    factory.afterPropertiesSet();

    assertNull(factory.getResource());
    assertEquals("PKCS11", factory.getType());
    assertEquals(MockSunPkcs11Provider.PROVIDER_BASE_NAME + "-Foo", factory.getProvider());
    assertEquals(cfgFile, factory.getPkcs11Configuration());

    final KeyStore ks = factory.getObject();
    assertNotNull(ks);
    assertEquals("PKCS11", ks.getType());
  }

  @Test
  public void testPkcs11StaticallyConfigured() throws Exception {
    Security.removeProvider(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
    Security.addProvider(MockSunPkcs11Provider.createStaticallyConfigured());

    final KeyStoreFactoryBean factory = new KeyStoreFactoryBean();
    factory.setPassword(PW);
    factory.setType("PKCS11");
    factory.setProvider(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
    factory.afterPropertiesSet();

    assertNull(factory.getResource());
    assertEquals("PKCS11", factory.getType());
    assertEquals(MockSunPkcs11Provider.PROVIDER_BASE_NAME, factory.getProvider());

    final KeyStore ks = factory.getObject();
    assertNotNull(ks);
    assertEquals("PKCS11", ks.getType());
  }

  @Test
  public void testPkcs11StaticallyConfiguredButHasConfig() {
    assertThrows(IllegalArgumentException.class, () -> {
      Security.removeProvider(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
      Security.addProvider(MockSunPkcs11Provider.createStaticallyConfigured());

      final KeyStoreFactoryBean factory = new KeyStoreFactoryBean();
      factory.setPassword(PW);
      factory.setType("PKCS11");
      factory.setProvider(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
      factory.setPkcs11Configuration((new ClassPathResource("cfg1.txt")).getFile().getAbsolutePath());
      factory.afterPropertiesSet();
    });
  }

  @Test
  public void testNoSuchProvider() {
    assertThrows(NoSuchProviderException.class, () -> {
      final KeyStoreFactoryBean factory = new KeyStoreFactoryBean();
      factory.setPassword(PW);
      factory.setType("PKCS11");
      factory.setProvider("NotProvider");
      factory.afterPropertiesSet();
    });
  }

  @Test
  public void testMissingPkcs11Configuration() {
    assertThrows(IllegalArgumentException.class, () -> {
      final KeyStoreFactoryBean factory = new KeyStoreFactoryBean();
      factory.setPassword(PW);
      factory.setType("PKCS11");
      factory.setProvider(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
      factory.afterPropertiesSet();
    });

  }

  // Won't work since we don't have a P11 device, but we exercise the code that defaults to
  // the SunPKCS11 provider ...
  @Test
  public void testSunPkcs11Provider() {
    assertThrows(ProviderException.class, () -> {
      final KeyStoreFactoryBean factory = new KeyStoreFactoryBean();
      factory.setPassword(PW);
      factory.setType("PKCS11");
      factory.setPkcs11Configuration((new ClassPathResource("cfg1.txt")).getFile().getAbsolutePath());
      factory.afterPropertiesSet();
    });
  }

}
