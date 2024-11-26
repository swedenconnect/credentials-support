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
package se.swedenconnect.security.credential.bundle;

import org.junit.jupiter.api.Test;
import se.swedenconnect.security.credential.config.DefaultConfigurationResourceLoader;
import se.swedenconnect.security.credential.config.properties.CredentialBundlesConfigurationProperties;
import se.swedenconnect.security.credential.config.properties.PemCredentialConfigurationProperties;
import se.swedenconnect.security.credential.config.properties.StoreConfigurationProperties;
import se.swedenconnect.security.credential.config.properties.StoreCredentialConfigurationProperties;

import java.security.KeyStoreException;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test cases for {@link ConfigurationCredentialBundleRegistrar}.
 *
 * @author Martin Lindström
 */
class ConfigurationCredentialBundleRegistrarTest {

  @Test
  void testRegister() {
    final CredentialBundleRegistry registry = new DefaultCredentialBundleRegistry();

    final CredentialBundlesConfigurationProperties configuration = new CredentialBundlesConfigurationProperties();

    configuration.setKeystore(new HashMap<>());
    final StoreConfigurationProperties storeConf = new StoreConfigurationProperties();
    storeConf.setLocation("classpath:rsa1.jks");
    storeConf.setPassword("secret");
    storeConf.setType("JKS");
    configuration.getKeystore().put("ks", storeConf);

    configuration.setPem(new HashMap<>());
    final PemCredentialConfigurationProperties pemConf = new PemCredentialConfigurationProperties();
    pemConf.setPrivateKey("classpath:rsa1.pkcs8.key");
    pemConf.setCertificates("classpath:rsa1.crt");
    configuration.getPem().put("pemcred", pemConf);

    configuration.setJks(new HashMap<>());
    final StoreCredentialConfigurationProperties jksConf = new StoreCredentialConfigurationProperties();
    jksConf.setStoreReference("ks");
    jksConf.setKey(new StoreCredentialConfigurationProperties.KeyConfigurationProperties());
    jksConf.getKey().setAlias("test");
    jksConf.getKey().setKeyPassword("secret");
    configuration.getJks().put("jkscred", jksConf);

    final ConfigurationCredentialBundleRegistrar registrar =
        new ConfigurationCredentialBundleRegistrar(configuration, new DefaultConfigurationResourceLoader());

    registrar.register(registry);

    final CredentialBundles bundles = (CredentialBundles) registry;

    assertNotNull(bundles.getCredential("pemcred"));
    assertThrows(NoSuchCredentialException.class, () -> bundles.getCredential("pemcred2"));
    assertNotNull(bundles.getCredentialProvider().apply("pemcred"));
    assertNull(bundles.getCredentialProvider().apply("pemcred2"));

    assertNotNull(bundles.getCredential("jkscred"));

    assertNotNull(bundles.getKeyStore("ks"));
    assertThrows(NoSuchKeyStoreException.class, () -> bundles.getKeyStore("ks2"));
    assertNotNull(bundles.getKeyStoreProvider().apply("ks"));
    assertNull(bundles.getKeyStoreProvider().apply("ks2"));
  }

  @Test
  void testRegisterFailedKeyStore() {
    final CredentialBundleRegistry registry = new DefaultCredentialBundleRegistry();

    final CredentialBundlesConfigurationProperties configuration = new CredentialBundlesConfigurationProperties();

    configuration.setKeystore(new HashMap<>());
    final StoreConfigurationProperties storeConf = new StoreConfigurationProperties();
    storeConf.setLocation("classpath:rsa1.jks");
    storeConf.setPassword("bad");
    configuration.getKeystore().put("ks", storeConf);

    final IllegalArgumentException ex =
        assertThrows(IllegalArgumentException.class, () -> ConfigurationCredentialBundleRegistrar.loadConfiguration(
            configuration, null, registry));
    assertTrue(ex.getCause() instanceof KeyStoreException);
  }

  @Test
  void testRegisterFailedPem() {
    final CredentialBundleRegistry registry = new DefaultCredentialBundleRegistry();

    final CredentialBundlesConfigurationProperties configuration = new CredentialBundlesConfigurationProperties();

    configuration.setPem(new HashMap<>());
    final PemCredentialConfigurationProperties pemConf = new PemCredentialConfigurationProperties();
    pemConf.setCertificates("classpath:rsa1.crt");
    pemConf.setPrivateKey("classpath:rsa1.pkcs8.enc.key");
    pemConf.setKeyPassword("bad");
    configuration.getPem().put("pemcred", pemConf);

    assertThrows(IllegalArgumentException.class, () -> ConfigurationCredentialBundleRegistrar.loadConfiguration(
        configuration, new DefaultConfigurationResourceLoader(), registry));
  }

  @Test
  void testRegisterFailedJks() {
    final CredentialBundleRegistry registry = new DefaultCredentialBundleRegistry();

    final CredentialBundlesConfigurationProperties configuration = new CredentialBundlesConfigurationProperties();

    configuration.setJks(new HashMap<>());
    final StoreCredentialConfigurationProperties jksConf = new StoreCredentialConfigurationProperties();
    jksConf.setStore(new StoreConfigurationProperties());
    jksConf.getStore().setLocation("classpath:rsa1.jks");
    jksConf.getStore().setPassword("bad");
    jksConf.setKey(new StoreCredentialConfigurationProperties.KeyConfigurationProperties());
    jksConf.getKey().setAlias("test");
    jksConf.getKey().setKeyPassword("secret");
    configuration.getJks().put("jkscred", jksConf);

    assertThrows(IllegalArgumentException.class, () -> ConfigurationCredentialBundleRegistrar.loadConfiguration(
        configuration, new DefaultConfigurationResourceLoader(), registry));
  }

  @Test
  void testRegisterEmpty() {
    final CredentialBundleRegistry registry = new DefaultCredentialBundleRegistry();
    final CredentialBundlesConfigurationProperties configuration = new CredentialBundlesConfigurationProperties();

    ConfigurationCredentialBundleRegistrar.loadConfiguration(
        configuration, new DefaultConfigurationResourceLoader(), registry);

    final CredentialBundles bundles = (CredentialBundles) registry;

    final NoSuchCredentialException ex = assertThrows(NoSuchCredentialException.class, () -> bundles.getCredential("test"));
    assertEquals("test", ex.getCredentialId());
    final NoSuchKeyStoreException ex2 = assertThrows(NoSuchKeyStoreException.class, () -> bundles.getKeyStore("test"));
    assertEquals("test", ex2.getKeyStoreId());
  }

  @Test
  void testDuplicateRegistrationKeyStore() {
    final DefaultCredentialBundleRegistry registry = new DefaultCredentialBundleRegistry();

    final CredentialBundlesConfigurationProperties configuration = new CredentialBundlesConfigurationProperties();

    configuration.setKeystore(new HashMap<>());
    final StoreConfigurationProperties storeConf = new StoreConfigurationProperties();
    storeConf.setLocation("classpath:rsa1.jks");
    storeConf.setPassword("secret");
    storeConf.setType("JKS");
    configuration.getKeystore().put("ks", storeConf);

    final ConfigurationCredentialBundleRegistrar registrar =
        new ConfigurationCredentialBundleRegistrar(configuration, new DefaultConfigurationResourceLoader());

    registrar.register(registry);

    final IllegalArgumentException ex =
        assertThrows(IllegalArgumentException.class, () ->
            registry.registerKeyStore("ks", ((CredentialBundles) registry).getKeyStore("ks")));
    assertEquals("A key store for 'ks' has already been registered", ex.getMessage());
  }

  @Test
  void testDuplicateRegistrationCredential() {
    final DefaultCredentialBundleRegistry registry = new DefaultCredentialBundleRegistry();

    final CredentialBundlesConfigurationProperties configuration = new CredentialBundlesConfigurationProperties();

    configuration.setPem(new HashMap<>());
    final PemCredentialConfigurationProperties pemConf = new PemCredentialConfigurationProperties();
    pemConf.setPrivateKey("classpath:rsa1.pkcs8.key");
    pemConf.setCertificates("classpath:rsa1.crt");
    configuration.getPem().put("pemcred", pemConf);

    final ConfigurationCredentialBundleRegistrar registrar =
        new ConfigurationCredentialBundleRegistrar(configuration, new DefaultConfigurationResourceLoader());

    registrar.register(registry);

    final IllegalArgumentException ex =
        assertThrows(IllegalArgumentException.class, () ->
            registry.registerCredential("pemcred", ((CredentialBundles) registry).getCredential("pemcred")));
    assertEquals("A credential for 'pemcred' has already been registered", ex.getMessage());
  }

}
