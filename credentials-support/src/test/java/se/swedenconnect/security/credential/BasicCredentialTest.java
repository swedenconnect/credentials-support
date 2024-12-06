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
package se.swedenconnect.security.credential;

import org.cryptacular.io.ClassPathResource;
import org.junit.jupiter.api.Test;
import se.swedenconnect.security.credential.factory.KeyStoreFactory;

import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test cases for BasicCredential.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
class BasicCredentialTest {

  private final PrivateKey privateKey;
  private final X509Certificate cert;

  private final PrivateKey privateKey2;
  private final X509Certificate cert2;

  public BasicCredentialTest() throws Exception {
    try (final InputStream is = new ClassPathResource("rsa1.jks").getInputStream()) {
      final KeyStore ks = KeyStoreFactory.loadKeyStore(is, "secret".toCharArray(), null, null);
      this.cert = (X509Certificate) ks.getCertificate("test");
      this.privateKey = (PrivateKey) ks.getKey("test", "secret".toCharArray());
    }
    try (final InputStream is = new ClassPathResource("rsa-dsa-ec.jks").getInputStream()) {
      final KeyStore ks = KeyStoreFactory.loadKeyStore(is, "secret".toCharArray(), null, null);
      this.cert2 = (X509Certificate) ks.getCertificate("rsa");
      this.privateKey2 = (PrivateKey) ks.getKey("rsa", "secret".toCharArray());
    }
  }

  @Test
  void testKeyPair() {
    final BasicCredential cred = new BasicCredential(new KeyPair(this.cert.getPublicKey(), this.privateKey));

    assertTrue(cred.getName().startsWith("RSA-"));
    assertNotNull(cred.getPrivateKey());
    assertNotNull(cred.getPublicKey());
    assertNull(cred.getCertificate());
    assertTrue(cred.getMetadata().getProperties().isEmpty());
  }

  @Test
  void testCertificate() {
    final BasicCredential cred = new BasicCredential(this.cert, this.privateKey);
    assertNotNull(cred.getPrivateKey());
    assertNotNull(cred.getPublicKey());
    assertNotNull(cred.getCertificate());
    assertEquals(2, cred.getMetadata().getProperties().size());
  }

  @Test
  void testMetadata() {
    final BasicCredential cred = new BasicCredential(this.cert, this.privateKey);
    final Instant issuedAt = Instant.ofEpochMilli(1668521306L);
    final Instant expiresAt = Instant.ofEpochMilli(1794751706L);
    cred.getMetadata().getProperties().put(PkiCredential.Metadata.ISSUED_AT_PROPERTY, issuedAt);
    cred.getMetadata().getProperties().put(PkiCredential.Metadata.EXPIRES_AT_PROPERTY, expiresAt);
    cred.getMetadata().getProperties().put(PkiCredential.Metadata.KEY_ID_PROPERTY, "12345");
    cred.getMetadata().getProperties().put("foo", "ABC");

    assertEquals("12345", cred.getMetadata().getKeyId());
    assertEquals(issuedAt, cred.getMetadata().getIssuedAt());
    assertEquals(expiresAt, cred.getMetadata().getExpiresAt());
    assertEquals("ABC", cred.getMetadata().getProperties().get("foo"));
  }

  @Test
  void testTransform() {
    final BasicCredential cred = new BasicCredential(this.cert, this.privateKey);
    final KeyPair keyPair = cred.transform(c -> new KeyPair(cred.getPublicKey(), cred.getPrivateKey()));
    assertNotNull(keyPair);
  }

  @Test
  void testDefaultNameCertSet() {
    final BasicCredential cred = new BasicCredential(this.cert, this.privateKey);

    assertEquals(this.cert.getSerialNumber().toString(10), cred.getName());
  }

  @Test
  void testDefaultNamePubKeySet() {
    final BasicCredential cred = new BasicCredential(this.cert.getPublicKey(), this.privateKey);
    assertTrue(cred.getName().startsWith("RSA-"));
  }

  @Test
  void testBadKeyPair() {
    final IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
        () -> new BasicCredential(this.cert.getPublicKey(), this.privateKey2));
    assertEquals("Public and private key do not make up a valid key pair", ex.getMessage());
  }

  @Test
  void testBadKeyPair2() {
    final IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
        () -> new BasicCredential(this.cert, this.privateKey2));
    assertEquals("Public key from certificate and private key do not make up a valid key pair", ex.getMessage());
  }

  @Test
  void testBadKeyPair3() {
    final IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
        () -> new BasicCredential(List.of(this.cert), this.privateKey2));
    assertEquals("Public key from entity certificate and private key do not make up a valid key pair", ex.getMessage());
  }

  @Test
  void testEmptyChain() {
    final IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
        () -> new BasicCredential(List.of(), this.privateKey));
    assertEquals("certificates must not be empty", ex.getMessage());
  }

}
