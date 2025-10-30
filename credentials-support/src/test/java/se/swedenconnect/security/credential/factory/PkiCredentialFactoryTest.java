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
package se.swedenconnect.security.credential.factory;

import org.cryptacular.io.ClassPathResource;
import org.cryptacular.io.Resource;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.KeyStoreCredentialTest;
import se.swedenconnect.security.credential.KeyStoreReloader;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.PkiCredentialCollection;
import se.swedenconnect.security.credential.bundle.CredentialBundles;
import se.swedenconnect.security.credential.bundle.NoSuchCredentialException;
import se.swedenconnect.security.credential.bundle.NoSuchKeyStoreException;
import se.swedenconnect.security.credential.config.properties.PemCredentialConfigurationProperties;
import se.swedenconnect.security.credential.config.properties.PkiCredentialCollectionConfigurationProperties;
import se.swedenconnect.security.credential.config.properties.PkiCredentialConfigurationProperties;
import se.swedenconnect.security.credential.config.properties.StoreConfigurationProperties;
import se.swedenconnect.security.credential.config.properties.StoreCredentialConfigurationProperties;
import se.swedenconnect.security.credential.pkcs11.MockSunPkcs11Provider;
import se.swedenconnect.security.credential.pkcs11.Pkcs11CredentialTest;
import se.swedenconnect.security.credential.pkcs11.Pkcs11KeyStoreReloader;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test cases for {@link PkiCredentialFactory}.
 *
 * @author Martin Lindström
 */
public class PkiCredentialFactoryTest {

  @Test
  void testInlinedPem() throws Exception {
    final String certificateContents = getContents("rsa1.crt");
    final String keyContents = getContents("rsa1.pkcs8.enc.key");

    final PemCredentialConfigurationProperties properties = new PemCredentialConfigurationProperties();
    properties.setName("test");
    properties.setCertificates(certificateContents);
    properties.setPrivateKey(keyContents);
    properties.setKeyPassword("secret");

    final PkiCredentialFactory factory = new PkiCredentialFactory(null, null, false);
    final PkiCredentialFactory factory2 = new PkiCredentialFactory(null, null, true);

    final PkiCredential credential = PkiCredentialFactory.createCredential(properties, null);
    assertNotNull(credential);
    assertEquals("test", credential.getName());
    assertEquals(1, credential.getCertificateChain().size());

    final PkiCredential credentialB = factory.createCredential(properties);
    assertNotNull(credentialB);
    assertEquals("test", credentialB.getName());
    assertEquals(1, credentialB.getCertificateChain().size());

    final PkiCredential credentialC = factory2.createCredential(properties);
    assertNotNull(credentialC);
    assertEquals("test", credentialC.getName());
    assertEquals(1, credentialC.getCertificateChain().size());

    final PkiCredential credentialC2 = factory2.createCredential(properties);
    assertNotNull(credentialC2);
    assertTrue(credentialC == credentialC2);

    final PkiCredentialConfigurationProperties pc = new PkiCredentialConfigurationProperties();
    pc.setPem(properties);

    final PkiCredential credential2 = PkiCredentialFactory.createCredential(pc, null, null, null, null);
    assertNotNull(credential2);
    assertEquals("test", credential2.getName());
    assertEquals(1, credential2.getCertificateChain().size());

    final PkiCredential credential2b = factory.createCredential(pc);
    assertNotNull(credential2b);
    assertEquals("test", credential2b.getName());
    assertEquals(1, credential2b.getCertificateChain().size());

    final PkiCredential credential2B = factory.createCredential(pc);
    assertNotNull(credential2B);
    assertEquals("test", credential2B.getName());

    final PkiCredential credential2C = factory2.createCredential(pc);
    assertNotNull(credential2C);
    assertEquals("test", credential2C.getName());

    final PkiCredential credential2C2 = factory2.createCredential(pc);
    assertNotNull(credentialC2);
    assertTrue(credential2C == credential2C2);
  }

  @Test
  void testInlinedPemKey() throws Exception {
    final String publicKeyContents = getContents("rsa1.pubkey.pem");
    final String keyContents = getContents("rsa1.pkcs8.enc.key");

    final PemCredentialConfigurationProperties properties = new PemCredentialConfigurationProperties();
    properties.setName("test");
    properties.setPublicKey(publicKeyContents);
    properties.setPrivateKey(keyContents);
    properties.setKeyPassword("secret");

    final PkiCredential credential = PkiCredentialFactory.createCredential(properties, null);
    assertNotNull(credential);
    assertEquals("test", credential.getName());
    assertNotNull(credential.getPublicKey());
    assertNull(credential.getCertificate());
    assertEquals(0, credential.getCertificateChain().size());

    final PkiCredentialConfigurationProperties pc = new PkiCredentialConfigurationProperties();
    pc.setPem(properties);

    final PkiCredential credential2 = PkiCredentialFactory.createCredential(pc, null, null, null, null);
    assertNotNull(credential2);
    assertEquals("test", credential2.getName());
    assertNotNull(credential2.getPublicKey());
  }

  @Test
  void testPem() throws Exception {
    final PemCredentialConfigurationProperties properties = new PemCredentialConfigurationProperties();
    properties.setName("test");
    properties.setCertificates("rsa1.crt");
    properties.setPrivateKey("rsa1.pkcs8.key");

    final PkiCredential credential = PkiCredentialFactory.createCredential(properties, null);
    assertNotNull(credential);
    assertEquals("test", credential.getName());
    assertEquals(1, credential.getCertificateChain().size());
  }

  @Test
  void testPemKey() throws Exception {
    final PemCredentialConfigurationProperties properties = new PemCredentialConfigurationProperties();
    properties.setName("test");
    properties.setPublicKey("rsa1.pubkey.pem");
    properties.setPrivateKey("rsa1.pkcs8.key");

    final PkiCredential credential = PkiCredentialFactory.createCredential(properties, null);
    assertNotNull(credential);
    assertEquals("test", credential.getName());
    assertNotNull(credential.getPublicKey());
    assertNull(credential.getCertificate());
    assertEquals(0, credential.getCertificateChain().size());
  }

  @Test
  void testPemMissingCertificateAndKey() {
    final PemCredentialConfigurationProperties properties = new PemCredentialConfigurationProperties();
    properties.setName("test");
    properties.setPrivateKey("rsa1.pkcs8.key");

    final IllegalArgumentException ex =
        assertThrows(IllegalArgumentException.class, () -> PkiCredentialFactory.createCredential(properties, null));
    assertEquals("Missing Certificate(s) or public key", ex.getMessage());
  }

  @Test
  void testBothCertificateAndKey() {
    final PemCredentialConfigurationProperties properties = new PemCredentialConfigurationProperties();
    properties.setName("test");
    properties.setCertificates("rsa1.crt");
    properties.setPublicKey("rsa1.pubkey.pem");
    properties.setPrivateKey("rsa1.pkcs8.key");

    final IllegalArgumentException ex =
        assertThrows(IllegalArgumentException.class, () -> PkiCredentialFactory.createCredential(properties, null));
    assertEquals("Certificate(s) and public key must not both be present", ex.getMessage());
  }

  @Test
  void testPemMissingKey() {
    final PemCredentialConfigurationProperties properties = new PemCredentialConfigurationProperties();
    properties.setName("test");
    properties.setCertificates("rsa1.crt");

    final IllegalArgumentException ex =
        assertThrows(IllegalArgumentException.class, () -> PkiCredentialFactory.createCredential(properties, null));
    assertEquals("No private key assigned", ex.getMessage());
  }

  @Test
  void testCredentialReference() throws Exception {
    final KeyStore keyStore;
    try (final InputStream inputStream = new ClassPathResource("rsa1.jks").getInputStream()) {
      keyStore = KeyStoreFactory.loadKeyStore(inputStream, "secret".toCharArray(), "JKS", null);
    }
    final PkiCredential credential = new KeyStoreCredential(keyStore, "test", "secret".toCharArray());

    final PkiCredentialConfigurationProperties configuration = new PkiCredentialConfigurationProperties();
    configuration.setBundle("bundle");

    final PkiCredential c = PkiCredentialFactory.createCredential(configuration, null, id -> credential, null, null);
    assertNotNull(c);
    assertTrue(credential == c);

    final PkiCredentialFactory factory = new PkiCredentialFactory(id -> credential, null, null, false);
    final PkiCredential cB = factory.createCredential(configuration);
    assertNotNull(cB);
    assertTrue(credential == cB);

    final CredentialBundles bundles = Mockito.mock(CredentialBundles.class);
    Mockito.when(bundles.getCredentialProvider()).thenReturn(id -> credential);

    final PkiCredentialFactory factory2 = new PkiCredentialFactory(bundles, null, false);
    final PkiCredential cC = factory2.createCredential(configuration);
    assertNotNull(cC);
    assertTrue(credential == cC);
  }

  @Test
  void testCredentialReferenceNotFound() {
    final PkiCredentialConfigurationProperties configuration = new PkiCredentialConfigurationProperties();
    configuration.setBundle("bundle");

    final NoSuchCredentialException ex = assertThrows(NoSuchCredentialException.class,
        () -> PkiCredentialFactory.createCredential(configuration, null, (String id) -> null, null, null));
    assertEquals("bundle", ex.getCredentialId());
  }

  @Test
  void testCredentialReferenceNoProvider() {
    final PkiCredentialConfigurationProperties configuration = new PkiCredentialConfigurationProperties();
    configuration.setBundle("bundle");

    assertThrows(IllegalArgumentException.class,
        () -> PkiCredentialFactory.createCredential(configuration, null, null, null, null));
  }

  @Test
  void testCredentialReferenceOtherAssigned() {
    final PkiCredentialConfigurationProperties configuration = new PkiCredentialConfigurationProperties();
    configuration.setBundle("bundle");
    configuration.setJks(new StoreCredentialConfigurationProperties());

    assertThrows(IllegalArgumentException.class,
        () -> PkiCredentialFactory.createCredential(configuration, null, null, null, null));

    configuration.setJks(null);
    configuration.setPem(new PemCredentialConfigurationProperties());
    assertThrows(IllegalArgumentException.class,
        () -> PkiCredentialFactory.createCredential(configuration, null, null, null, null));
  }

  @Test
  void testStoreReference() throws Exception {
    final KeyStore keyStore;
    try (final InputStream inputStream = new ClassPathResource("rsa1.jks").getInputStream()) {
      keyStore = KeyStoreFactory.loadKeyStore(inputStream, "secret".toCharArray(), "JKS", null);
    }
    final KeyStoreReloader reloader = new Pkcs11KeyStoreReloader("secret".toCharArray());

    final StoreCredentialConfigurationProperties properties = new StoreCredentialConfigurationProperties();
    properties.setName("test");
    properties.setStoreReference("myKeyStore");
    properties.setKey(new StoreCredentialConfigurationProperties.KeyConfigurationProperties());
    properties.getKey().setAlias("test");
    properties.getKey().setKeyPassword("secret");

    final PkiCredentialFactory factory = new PkiCredentialFactory(null, i -> keyStore, null, false);
    final PkiCredentialFactory factory2 = new PkiCredentialFactory(null, i -> keyStore, null, true);

    final PkiCredential credential = PkiCredentialFactory.createCredential(properties, null,
        i -> keyStore, i -> reloader);
    assertNotNull(credential);
    assertEquals("test", credential.getName());
    assertEquals(1, credential.getCertificateChain().size());

    final PkiCredential credentialB = factory.createCredential(properties);
    assertNotNull(credentialB);
    assertEquals("test", credentialB.getName());
    assertEquals(1, credentialB.getCertificateChain().size());

    final PkiCredential credentialC = factory2.createCredential(properties);
    assertNotNull(credentialC);
    assertEquals("test", credentialC.getName());

    final PkiCredential credentialC2 = factory2.createCredential(properties);
    assertNotNull(credentialC2);
    assertEquals("test", credentialC2.getName());
    final PkiCredential credentialC22 = factory2.createCredential(properties);
    assertTrue(credentialC2 == credentialC22);

    final PkiCredentialConfigurationProperties pc = new PkiCredentialConfigurationProperties();
    pc.setJks(properties);

    final PkiCredential credential2 = PkiCredentialFactory.createCredential(pc, null, null,
        i -> keyStore, i -> reloader);
    assertNotNull(credential2);
    assertEquals("test", credential2.getName());
    assertEquals(1, credential2.getCertificateChain().size());
  }

  @Test
  void testStoreReferenceNoSupplier() {
    final StoreCredentialConfigurationProperties properties = new StoreCredentialConfigurationProperties();
    properties.setName("test");
    properties.setStoreReference("myKeyStore");
    properties.setKey(new StoreCredentialConfigurationProperties.KeyConfigurationProperties());
    properties.getKey().setAlias("test");
    properties.getKey().setKeyPassword("secret");

    final IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
        PkiCredentialFactory.createCredential(properties, null, null, null));
    assertEquals("No key store provider provided - can not resolve store reference", ex.getMessage());
  }

  @Test
  void testStoreReferenceNoStoreFound() {
    final StoreCredentialConfigurationProperties properties = new StoreCredentialConfigurationProperties();
    properties.setName("test");
    properties.setStoreReference("myKeyStore");
    properties.setKey(new StoreCredentialConfigurationProperties.KeyConfigurationProperties());
    properties.getKey().setAlias("test");
    properties.getKey().setKeyPassword("secret");

    final NoSuchKeyStoreException ex = assertThrows(NoSuchKeyStoreException.class, () ->
        PkiCredentialFactory.createCredential(properties, null, r -> null, r -> null));
    assertEquals("myKeyStore", ex.getKeyStoreId());
    assertEquals("Referenced store 'myKeyStore' is not present", ex.getMessage());
  }

  @Test
  void testNoStore() {
    final StoreCredentialConfigurationProperties properties = new StoreCredentialConfigurationProperties();
    properties.setName("test");
    properties.setKey(new StoreCredentialConfigurationProperties.KeyConfigurationProperties());
    properties.getKey().setAlias("test");
    properties.getKey().setKeyPassword("secret");

    final IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
        PkiCredentialFactory.createCredential(properties, null, null, null));
    assertEquals("No store or store-reference assigned", ex.getMessage());
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

    final PkiCredential credential = PkiCredentialFactory.createCredential(properties, null, null, null);
    assertNotNull(credential);
    assertEquals("test", credential.getName());
    assertEquals(1, credential.getCertificateChain().size());
  }

  @Test
  void testStoreAndReference() {
    final StoreCredentialConfigurationProperties properties = new StoreCredentialConfigurationProperties();
    properties.setName("test");
    properties.setStoreReference("ref");
    properties.setStore(new StoreConfigurationProperties());
    properties.getStore().setLocation("rsa1.jks");
    properties.getStore().setPassword("secret");
    properties.setKey(new StoreCredentialConfigurationProperties.KeyConfigurationProperties());
    properties.getKey().setAlias("test");

    final IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, ()
        -> PkiCredentialFactory.createCredential(properties, null, null, null));
    assertEquals("Both store and store-reference can not be set", ex.getMessage());
  }

  @Test
  void testStoreReferenceNoKeyPassword() throws Exception {
    final KeyStore keyStore;
    try (final InputStream inputStream = new ClassPathResource("rsa1.jks").getInputStream()) {
      keyStore = KeyStoreFactory.loadKeyStore(inputStream, "secret".toCharArray(), "JKS", null);
    }
    final StoreCredentialConfigurationProperties properties = new StoreCredentialConfigurationProperties();
    properties.setName("test");
    properties.setStoreReference("myKeyStore");
    properties.setKey(new StoreCredentialConfigurationProperties.KeyConfigurationProperties());
    properties.getKey().setAlias("test");

    final IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
        PkiCredentialFactory.createCredential(properties, null, i -> keyStore, null));
    assertEquals("No key password given, and can not get store password since store reference was used",
        ex.getMessage());
  }

  @Test
  void testStoreMissingKey() {
    final StoreCredentialConfigurationProperties properties = new StoreCredentialConfigurationProperties();
    properties.setName("test");
    properties.setStore(new StoreConfigurationProperties());
    properties.getStore().setLocation("rsa1.jks");
    properties.getStore().setPassword("secret");

    final IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
        PkiCredentialFactory.createCredential(properties, null, null, null));
    assertEquals("No key entry assigned", ex.getMessage());
  }

  @Test
  void testStoreMissingAlias() {
    final StoreCredentialConfigurationProperties properties = new StoreCredentialConfigurationProperties();
    properties.setName("test");
    properties.setStore(new StoreConfigurationProperties());
    properties.getStore().setLocation("rsa1.jks");
    properties.getStore().setPassword("secret");
    properties.setKey(new StoreCredentialConfigurationProperties.KeyConfigurationProperties());

    final IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
        PkiCredentialFactory.createCredential(properties, null, null, null));
    assertEquals("No key entry alias assigned", ex.getMessage());
  }

  @Test
  void testStoreAdditionalCert() throws Exception {
    final StoreCredentialConfigurationProperties properties = new StoreCredentialConfigurationProperties();
    properties.setName("test");
    properties.setStore(new StoreConfigurationProperties());
    properties.getStore().setLocation("rsa1.jks");
    properties.getStore().setPassword("secret");
    properties.setKey(new StoreCredentialConfigurationProperties.KeyConfigurationProperties());
    properties.getKey().setAlias("test");
    properties.getKey().setKeyPassword("secret");
    properties.getKey().setCertificates("rsa1.crt");

    final PkiCredential credential = PkiCredentialFactory.createCredential(properties, null, null, null);
    assertNotNull(credential);
    assertEquals("test", credential.getName());
    assertEquals(1, credential.getCertificateChain().size());
  }

  @Test
  void testStoreAdditionalCertInlined() throws Exception {
    final StoreCredentialConfigurationProperties properties = new StoreCredentialConfigurationProperties();
    properties.setName("test");
    properties.setStore(new StoreConfigurationProperties());
    properties.getStore().setLocation("rsa1.jks");
    properties.getStore().setPassword("secret");
    properties.setKey(new StoreCredentialConfigurationProperties.KeyConfigurationProperties());
    properties.getKey().setAlias("test");
    properties.getKey().setKeyPassword("secret");
    properties.getKey().setCertificates(getContents("rsa1.crt"));

    final PkiCredential credential = PkiCredentialFactory.createCredential(properties, null, null, null);
    assertNotNull(credential);
    assertEquals("test", credential.getName());
    assertEquals(1, credential.getCertificateChain().size());
  }

  @Test
  void testInvalidPkiCredentialConfiguration() {
    final PkiCredentialConfigurationProperties pc = new PkiCredentialConfigurationProperties();
    assertThrows(IllegalArgumentException.class,
        () -> PkiCredentialFactory.createCredential(pc, null, null, null, null));

    final PkiCredentialConfigurationProperties pc2 = new PkiCredentialConfigurationProperties();
    pc2.setPem(new PemCredentialConfigurationProperties());
    pc2.setJks(new StoreCredentialConfigurationProperties());
    assertThrows(IllegalArgumentException.class,
        () -> PkiCredentialFactory.createCredential(pc2, null, null, null, null));
  }

  @Test
  void testMetadata() throws Exception {
    final StoreCredentialConfigurationProperties properties = new StoreCredentialConfigurationProperties();
    properties.setName("test");
    properties.setStore(new StoreConfigurationProperties());
    properties.getStore().setLocation("rsa1.jks");
    properties.getStore().setPassword("secret");
    properties.setKey(new StoreCredentialConfigurationProperties.KeyConfigurationProperties());
    properties.getKey().setAlias("test");

    properties.setKeyId("12345");
    final Instant issuedAt = Instant.ofEpochMilli(1668521306L);
    final Instant expiresAt = Instant.ofEpochMilli(1794751706L);
    properties.setIssuedAt(issuedAt);
    properties.setExpiresAt(expiresAt);
    properties.getMetadata().put("foo", "ABC");

    final PkiCredential credential = PkiCredentialFactory.createCredential(properties, null, null, null);
    assertNotNull(credential);
    assertEquals("test", credential.getName());
    assertEquals(1, credential.getCertificateChain().size());

    assertEquals("12345", credential.getMetadata().getKeyId());
    assertEquals(issuedAt, credential.getMetadata().getIssuedAt());
    assertEquals(expiresAt, credential.getMetadata().getExpiresAt());
    assertEquals("ABC", credential.getMetadata().getProperties().get("foo"));
  }

  @Test
  void testPkcs11() throws Exception {
    KeyStoreCredentialTest.initPkcs11Mock();
    try {
      final StoreCredentialConfigurationProperties properties = new StoreCredentialConfigurationProperties();
      properties.setName("test");
      properties.setStore(new StoreConfigurationProperties());
      properties.getStore().setType("PKCS11");
      properties.getStore().setProvider(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
      properties.getStore().setPassword("secret");
      properties.getStore().setPkcs11(new StoreConfigurationProperties.Pkcs11ConfigurationProperties());
      properties.getStore().getPkcs11().setConfigurationFile(Pkcs11CredentialTest.getAbsolutePath("cfg1.txt"));
      properties.setMonitor(true);
      properties.setKey(new StoreCredentialConfigurationProperties.KeyConfigurationProperties());
      properties.getKey().setAlias("test");
      properties.getKey().setKeyPassword("secret");
      properties.getKey().setCertificates("rsa1.crt");

      final PkiCredential credential =
          PkiCredentialFactory.createCredential(properties, null, null, null);
      assertNotNull(credential);
      assertTrue(credential.isHardwareCredential());
    }
    finally {
      KeyStoreCredentialTest.cleanupPkcs11Mock();
    }
  }

  @Test
  void testCollection() throws Exception {
    final StoreConfigurationProperties storeProps = new StoreConfigurationProperties();
    storeProps.setType("JKS");
    storeProps.setLocation("keys.jks");
    storeProps.setPassword("secret");

    final PkiCredentialConfigurationProperties p1 = new PkiCredentialConfigurationProperties();
    p1.setJks(new StoreCredentialConfigurationProperties());
    p1.getJks().setName("rsa");
    p1.getJks().setStore(storeProps);
    p1.getJks().setKey(new StoreCredentialConfigurationProperties.KeyConfigurationProperties());
    p1.getJks().getKey().setAlias("rsa");

    final PkiCredentialConfigurationProperties p2 = new PkiCredentialConfigurationProperties();
    p2.setJks(new StoreCredentialConfigurationProperties());
    p2.getJks().setName("rsa2");
    p2.getJks().setStore(storeProps);
    p2.getJks().setKey(new StoreCredentialConfigurationProperties.KeyConfigurationProperties());
    p2.getJks().getKey().setAlias("rsa2");

    final PkiCredentialCollectionConfigurationProperties conf = new PkiCredentialCollectionConfigurationProperties();
    conf.setCredentials(List.of(p1, p2));

    final PkiCredentialCollection collection1 =
        PkiCredentialFactory.createCredentialCollection(conf, null, null, null, null);
    Assertions.assertEquals(2, collection1.getCredentials().size());

    final PkiCredentialFactory factory = new PkiCredentialFactory(null, null, null, true);
    final PkiCredentialCollection collection2 = factory.createCredentialCollection(conf);
    Assertions.assertEquals(2, collection2.getCredentials().size());
  }

  private static String getContents(final String resource) throws IOException {
    final Resource r = new ClassPathResource(resource);
    try (final InputStream is = r.getInputStream()) {
      return new String(is.readAllBytes());
    }
  }

}
