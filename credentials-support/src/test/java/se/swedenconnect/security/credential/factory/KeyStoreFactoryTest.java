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
package se.swedenconnect.security.credential.factory;

import org.cryptacular.io.ClassPathResource;
import org.cryptacular.io.Resource;
import org.junit.jupiter.api.Test;
import se.swedenconnect.security.credential.config.properties.StoreConfigurationProperties;
import se.swedenconnect.security.credential.pkcs11.FilePkcs11Configuration;
import se.swedenconnect.security.credential.pkcs11.MockSunPkcs11Provider;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test cases for {@link se.swedenconnect.security.credential.factory.KeyStoreFactory}.
 *
 * @author Martin Lindström
 */
public class KeyStoreFactoryTest {

  @Test
  void testLoadKeyStore() throws Exception {
    final Resource resource = new ClassPathResource("rsa1.jks");
    try (final InputStream is = resource.getInputStream()) {
      final KeyStore keyStore = KeyStoreFactory.loadKeyStore(is, "secret".toCharArray(), "JKS", "SUN");
      assertNotNull(keyStore);
    }
  }

  @Test
  void testLoadKeyStoreNoTypeOfProvider() throws Exception {
    final Resource resource = new ClassPathResource("rsa1.jks");
    try (final InputStream is = resource.getInputStream()) {
      final KeyStore keyStore = KeyStoreFactory.loadKeyStore(is, "secret".toCharArray(), null, null);
      assertNotNull(keyStore);
    }
  }

  @Test
  void testLoadKeyStoreBadPassword() throws Exception {
    final Resource resource = new ClassPathResource("rsa1.jks");
    try (final InputStream is = resource.getInputStream()) {
      assertThrows(KeyStoreException.class, () -> KeyStoreFactory.loadKeyStore(is, "bad".toCharArray(), null, null));
    }
  }

  @Test
  void testLoadKeyStoreBadUse() throws Exception {
    final Resource resource = new ClassPathResource("rsa1.jks");
    try (final InputStream is = resource.getInputStream()) {
      final IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
          () -> KeyStoreFactory.loadKeyStore(is, "secret".toCharArray(), "PKCS11", null));
      assertEquals("PKCS11 keystore type not supported by createKeyStore", ex.getMessage());
    }
  }

  @Test
  void testLoadPkcs11KeyStore() throws Exception {
    try {
      setupPkcs11();

      final FilePkcs11Configuration configuration = new FilePkcs11Configuration(
          getAbsolutePath("cfg1.txt"), MockSunPkcs11Provider.PROVIDER_BASE_NAME);

      final KeyStore keyStore = KeyStoreFactory.loadPkcs11KeyStore(configuration, "secret".toCharArray());
      assertNotNull(keyStore);
      assertNotNull(keyStore.getKey("test", "secret".toCharArray()));
    }
    finally {
      tearDownPkcs11();
    }
  }

  @Test
  void testLoadPkcs11KeyStoreBadPin() throws Exception {
    try {
      setupPkcs11();

      final FilePkcs11Configuration configuration = new FilePkcs11Configuration(
          getAbsolutePath("cfg1.txt"), MockSunPkcs11Provider.PROVIDER_BASE_NAME);

      assertThrows(KeyStoreException.class,
          () -> KeyStoreFactory.loadPkcs11KeyStore(configuration, "bad".toCharArray()));
    }
    finally {
      tearDownPkcs11();
    }
  }

  @Test
  void testLoadKeyStoreFromConf() throws Exception {
    final StoreConfigurationProperties configuration = new StoreConfigurationProperties();
    configuration.setLocation("classpath:rsa1.jks");
    configuration.setPassword("secret");
    final KeyStore keyStore = KeyStoreFactory.loadKeyStore(configuration, null);
    assertNotNull(keyStore);
  }

  @Test
  void testLoadKeyStoreMissingLocation() throws Exception {
    final StoreConfigurationProperties configuration = new StoreConfigurationProperties();
    configuration.setPassword("secret");
    final IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
        KeyStoreFactory.loadKeyStore(configuration, null));
    assertEquals("location must be set", ex.getMessage());
  }

  @Test
  void testLoadPkcs11KeyStoreFromFileConf() throws Exception {
    try {
      setupPkcs11();

      final StoreConfigurationProperties configuration = new StoreConfigurationProperties();
      configuration.setPassword("secret");
      configuration.setType("PKCS11");
      configuration.setProvider(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
      configuration.setPkcs11(new StoreConfigurationProperties.Pkcs11ConfigurationProperties());
      configuration.getPkcs11().setConfigurationFile(getAbsolutePath("cfg1.txt"));

      final KeyStore keyStore = KeyStoreFactory.loadKeyStore(configuration, null);
      assertNotNull(keyStore);
      assertNotNull(keyStore.getKey("test", "secret".toCharArray()));
    }
    finally {
      tearDownPkcs11();
    }
  }

  @Test
  void testLoadPkcs11KeyStoreFromCustomConf() throws Exception {
    try {
      setupPkcs11();

      final StoreConfigurationProperties configuration = new StoreConfigurationProperties();
      configuration.setPassword("secret");
      configuration.setType("PKCS11");
      configuration.setProvider(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
      configuration.setPkcs11(new StoreConfigurationProperties.Pkcs11ConfigurationProperties());
      configuration.getPkcs11()
          .setSettings(new StoreConfigurationProperties.Pkcs11ConfigurationProperties.Pkcs11SettingsProperties());
      configuration.getPkcs11().getSettings().setName("Foo");
      configuration.getPkcs11().getSettings().setLibrary("/opt/foo/lib/libpkcs11.so");

      final KeyStore keyStore = KeyStoreFactory.loadKeyStore(configuration, null);
      assertNotNull(keyStore);
      assertNotNull(keyStore.getKey("test", "secret".toCharArray()));
    }
    finally {
      tearDownPkcs11();
    }
  }

  @Test
  void testLoadPkcs11KeyStoreFromCustomConfMissingName() throws Exception {
    try {
      setupPkcs11();

      final StoreConfigurationProperties configuration = new StoreConfigurationProperties();
      configuration.setPassword("secret");
      configuration.setType("PKCS11");
      configuration.setProvider(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
      configuration.setPkcs11(new StoreConfigurationProperties.Pkcs11ConfigurationProperties());
      configuration.getPkcs11()
          .setSettings(new StoreConfigurationProperties.Pkcs11ConfigurationProperties.Pkcs11SettingsProperties());
      configuration.getPkcs11().getSettings().setLibrary("/opt/foo/lib/libpkcs11.so");

      final IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
          KeyStoreFactory.loadKeyStore(configuration, null));
      assertEquals("Invalid custom PKCS#11 configuration - name and library must be supplied", ex.getMessage());

    }
    finally {
      tearDownPkcs11();
    }
  }

  @Test
  void testLoadPkcs11KeyStoreFromCustomConfMissingLibrary() throws Exception {
    try {
      setupPkcs11();

      final StoreConfigurationProperties configuration = new StoreConfigurationProperties();
      configuration.setPassword("secret");
      configuration.setType("PKCS11");
      configuration.setProvider(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
      configuration.setPkcs11(new StoreConfigurationProperties.Pkcs11ConfigurationProperties());
      configuration.getPkcs11()
          .setSettings(new StoreConfigurationProperties.Pkcs11ConfigurationProperties.Pkcs11SettingsProperties());
      configuration.getPkcs11().getSettings().setName("Foo");

      final IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
          KeyStoreFactory.loadKeyStore(configuration, null));
      assertEquals("Invalid custom PKCS#11 configuration - name and library must be supplied", ex.getMessage());

    }
    finally {
      tearDownPkcs11();
    }
  }

  @Test
  void testLoadPkcs11KeyStoreBadConf() throws Exception {
    try {
      setupPkcs11();

      final StoreConfigurationProperties configuration = new StoreConfigurationProperties();
      configuration.setPassword("secret");
      configuration.setType("PKCS11");
      configuration.setProvider(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
      configuration.setPkcs11(new StoreConfigurationProperties.Pkcs11ConfigurationProperties());

      final IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
          KeyStoreFactory.loadKeyStore(configuration, null));
      assertEquals("Invalid PKCS#11 configuration - could not create provider", ex.getMessage());

    }
    finally {
      tearDownPkcs11();
    }
  }

  @Test
  void testLoadPkcs11KeyStoreFromStaticConf() throws Exception {
    try {
      setupPkcs11();

      final FilePkcs11Configuration setupConf =
          new FilePkcs11Configuration(getAbsolutePath("cfg1.txt"), MockSunPkcs11Provider.PROVIDER_BASE_NAME);
      setupConf.init();
      final Provider provider = setupConf.getProvider();

      final StoreConfigurationProperties configuration = new StoreConfigurationProperties();
      configuration.setPassword("secret");
      configuration.setType("PKCS11");
      configuration.setProvider(provider.getName());

      final KeyStore keyStore = KeyStoreFactory.loadKeyStore(configuration, null);
      assertNotNull(keyStore);
      assertNotNull(keyStore.getKey("test", "secret".toCharArray()));
    }
    finally {
      tearDownPkcs11();
    }
  }

  public static String getAbsolutePath(final String resource) {
    final String p = resource.startsWith("/") ? "" : "/";
    return System.getProperty("user.dir") + "/src/test/resources" + p + resource;
  }

  public static void setupPkcs11() {
    Security.insertProviderAt(new MockSunPkcs11Provider(), 1);
    // We let rsa1.jks simulate our PKCS#11 device
    MockSunPkcs11Provider.MockedPkcs11ResourceHolder.getInstance().setResource(new ClassPathResource("rsa1.jks"));
  }

  public static void tearDownPkcs11() {
    Security.removeProvider(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
    final Provider[] providers = Security.getProviders();
    for (final Provider p : providers) {
      if (p.getName().contains(MockSunPkcs11Provider.PROVIDER_BASE_NAME)) {
        Security.removeProvider(p.getName());
      }
    }
    MockSunPkcs11Provider.MockedPkcs11ResourceHolder.getInstance().setResource(null);
  }

}
