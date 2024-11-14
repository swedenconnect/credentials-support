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

import org.cryptacular.io.ClassPathResource;
import org.cryptacular.io.Resource;
import org.junit.jupiter.api.Test;
import se.swedenconnect.security.credential.KeyStoreReloader;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.config.properties.PemCredentialConfigurationProperties;
import se.swedenconnect.security.credential.config.properties.PkiCredentialConfigurationProperties;
import se.swedenconnect.security.credential.config.properties.StoreConfigurationProperties;
import se.swedenconnect.security.credential.config.properties.StoreCredentialConfigurationProperties;
import se.swedenconnect.security.credential.pkcs11.Pkcs11KeyStoreReloader;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test cases for {@link PkiCredentialFactory}.
 *
 * @author Martin Lindström
 */
class PkiCredentialFactoryTest {

  @Test
  void testInlinedPem() throws Exception {
    final String certificateContents = getContents("rsa1.crt");
    final String keyContents = getContents("rsa1.pkcs8.enc.key");

    final PemCredentialConfigurationProperties properties = new PemCredentialConfigurationProperties();
    properties.setName("test");
    properties.setCertificates(certificateContents);
    properties.setPrivateKey(keyContents);
    properties.setKeyPassword("secret");

    final PkiCredential credential = PkiCredentialFactory.createCredential(properties, null);
    assertNotNull(credential);
    assertEquals("test", credential.getName());
    assertEquals(1, credential.getCertificateChain().size());

    final PkiCredentialConfigurationProperties pc = new PkiCredentialConfigurationProperties();
    pc.setPem(properties);

    final PkiCredential credential2 = PkiCredentialFactory.createCredential(pc, null, null, null);
    assertNotNull(credential2);
    assertEquals("test", credential2.getName());
    assertEquals(1, credential2.getCertificateChain().size());
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
  void testPemMissingCertificate() {
    final PemCredentialConfigurationProperties properties = new PemCredentialConfigurationProperties();
    properties.setName("test");
    properties.setPrivateKey("rsa1.pkcs8.key");

    final IllegalArgumentException ex =
        assertThrows(IllegalArgumentException.class, () -> PkiCredentialFactory.createCredential(properties, null));
    assertEquals("No certificate/s assigned", ex.getMessage());
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

    final PkiCredential credential = PkiCredentialFactory.createCredential(properties, null,
        i -> keyStore, i -> reloader);
    assertNotNull(credential);
    assertEquals("test", credential.getName());
    assertEquals(1, credential.getCertificateChain().size());

    final PkiCredentialConfigurationProperties pc = new PkiCredentialConfigurationProperties();
    pc.setJks(properties);

    final PkiCredential credential2 = PkiCredentialFactory.createCredential(pc, null,
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
    assertEquals("No key store supplier provided - can not resolve store reference", ex.getMessage());
  }

  @Test
  void testStoreReferenceNoStoreFound() {
    final StoreCredentialConfigurationProperties properties = new StoreCredentialConfigurationProperties();
    properties.setName("test");
    properties.setStoreReference("myKeyStore");
    properties.setKey(new StoreCredentialConfigurationProperties.KeyConfigurationProperties());
    properties.getKey().setAlias("test");
    properties.getKey().setKeyPassword("secret");

    final IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
        PkiCredentialFactory.createCredential(properties, null, r -> null, r -> null));
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
    assertThrows(IllegalArgumentException.class, () -> PkiCredentialFactory.createCredential(pc, null, null, null));

    final PkiCredentialConfigurationProperties pc2 = new PkiCredentialConfigurationProperties();
    pc2.setPem(new PemCredentialConfigurationProperties());
    pc2.setJks(new StoreCredentialConfigurationProperties());
    assertThrows(IllegalArgumentException.class, () -> PkiCredentialFactory.createCredential(pc2, null, null, null));
  }

  private static String getContents(final String resource) throws IOException {
    final Resource r = new ClassPathResource(resource);
    try (final InputStream is = r.getInputStream()) {
      return new String(is.readAllBytes());
    }
  }
}
