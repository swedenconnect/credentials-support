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
package se.swedenconnect.security.credential.utils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cryptacular.io.ClassPathResource;
import org.cryptacular.io.Resource;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyException;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test cases for KeyUtils.
 *
 * @author Martin Lindström
 */
class KeyUtilsTest {

  @BeforeAll
  static void setUp() {
    if (Security.getProvider("BC") == null) {
      Security.insertProviderAt(new BouncyCastleProvider(), 2);
    }
  }

  @Test
  void testIsInlinedPem() throws Exception {
    assertFalse(KeyUtils.isInlinedPem("classpath:file.key"));
    assertTrue(KeyUtils.isInlinedPem(new String(getResourceBytes(new ClassPathResource("rsa1.openssl.key")))));
  }

  @Test
  void testRsaPemPublicKey() throws Exception {
    final byte[] contents = getResourceBytes(new ClassPathResource("rsa1.pubkey.pem"));
    try (final InputStream is = new ByteArrayInputStream(contents)) {
      assertNotNull(KeyUtils.decodePublicKey(is));
    }
    assertNotNull(KeyUtils.decodePublicKey(contents));
  }

  @Test
  void testRsaDerPublicKey() throws Exception {
    final byte[] contents = getResourceBytes(new ClassPathResource("rsa1.pubkey.der"));
    try (final InputStream is = new ByteArrayInputStream(contents)) {
      assertNotNull(KeyUtils.decodePublicKey(is));
    }
    assertNotNull(KeyUtils.decodePublicKey(contents));
  }

  @Test
  void testEcPemPublicKey() throws Exception {
    final byte[] contents = getResourceBytes(new ClassPathResource("ec.pubkey.pem"));
    try (final InputStream is = new ByteArrayInputStream(contents)) {
      assertNotNull(KeyUtils.decodePublicKey(is));
    }
    assertNotNull(KeyUtils.decodePublicKey(contents));
  }

  @Test
  void testEcDerPublicKey() throws Exception {
    final byte[] contents = getResourceBytes(new ClassPathResource("ec.pubkey.der"));
    try (final InputStream is = new ByteArrayInputStream(contents)) {
      assertNotNull(KeyUtils.decodePublicKey(is));
    }
    assertNotNull(KeyUtils.decodePublicKey(contents));
  }

  @Test
  void testOpenSslRsaKey() throws Exception {
    final byte[] contents = getResourceBytes(new ClassPathResource("rsa1.openssl.key"));
    try (final InputStream is = new ByteArrayInputStream(contents)) {
      assertNotNull(KeyUtils.decodePrivateKey(is));
    }
    assertNotNull(KeyUtils.decodePrivateKey(contents));
  }

  @Test
  void testEncryptedOpenSslRsaKey() throws Exception {
    final byte[] contents = getResourceBytes(new ClassPathResource("rsa1.openssl.enc.key"));
    try (final InputStream is = new ByteArrayInputStream(contents)) {
      assertNotNull(KeyUtils.decodePrivateKey(is, "secret".toCharArray()));
    }
    assertNotNull(KeyUtils.decodePrivateKey(contents, "secret".toCharArray()));
  }

  @Test
  void testPkcs8RsaKey() throws Exception {
    final byte[] contents = getResourceBytes(new ClassPathResource("rsa1.pkcs8.key"));
    try (final InputStream is = new ByteArrayInputStream(contents)) {
      assertNotNull(KeyUtils.decodePrivateKey(is));
    }
    assertNotNull(KeyUtils.decodePrivateKey(contents));
  }

  @Test
  void testEncryptedPkcs8RsaKey() throws Exception {
    final byte[] contents = getResourceBytes(new ClassPathResource("rsa1.pkcs8.enc.key"));
    try (final InputStream is = new ByteArrayInputStream(contents)) {
      assertNotNull(KeyUtils.decodePrivateKey(is, "secret".toCharArray()));
    }
    assertNotNull(KeyUtils.decodePrivateKey(contents, "secret".toCharArray()));
  }

  @Test
  void testOpenSslEcKey() throws Exception {
    final byte[] contents = getResourceBytes(new ClassPathResource("ec.openssl.key"));
    try (final InputStream is = new ByteArrayInputStream(contents)) {
      assertNotNull(KeyUtils.decodePrivateKey(is));
    }
    assertNotNull(KeyUtils.decodePrivateKey(contents));
  }

  @Test
  void testEncryptedOpenSslEcKey() throws Exception {
    final byte[] contents = getResourceBytes(new ClassPathResource("ec.openssl.enc.key"));
    try (final InputStream is = new ByteArrayInputStream(contents)) {
      assertNotNull(KeyUtils.decodePrivateKey(is, "secret".toCharArray()));
    }
    assertNotNull(KeyUtils.decodePrivateKey(contents, "secret".toCharArray()));
  }

  @Test
  void testPkcs8EcKey() throws Exception {
    final byte[] contents = getResourceBytes(new ClassPathResource("ec.pkcs8.key"));
    try (final InputStream is = new ByteArrayInputStream(contents)) {
      assertNotNull(KeyUtils.decodePrivateKey(is));
    }
    assertNotNull(KeyUtils.decodePrivateKey(contents));
  }

  @Test
  void testEncryptedPkcs8EcKey() throws Exception {
    final byte[] contents = getResourceBytes(new ClassPathResource("ec.pkcs8.enc.key"));
    try (final InputStream is = new ByteArrayInputStream(contents)) {
      assertNotNull(KeyUtils.decodePrivateKey(is, "secret".toCharArray()));
    }
    assertNotNull(KeyUtils.decodePrivateKey(contents, "secret".toCharArray()));
  }

  @Test
  void testEncodingError() throws Exception {
    assertThrows(KeyException.class, () -> KeyUtils.decodePrivateKey("NOT A KEY".getBytes()));
    try (final InputStream is = new ByteArrayInputStream("not a key".getBytes())) {
      assertThrows(KeyException.class, () -> KeyUtils.decodePrivateKey(is));
    }
  }

  @Test
  void testEncodingError2() throws Exception {
    assertThrows(KeyException.class, () -> KeyUtils.decodePublicKey("NOT A KEY".getBytes()));
    try (final InputStream is = new ByteArrayInputStream("not a key".getBytes())) {
      assertThrows(KeyException.class, () -> KeyUtils.decodePrivateKey(is));
    }
  }

  @Test
  void testBadPassword() throws Exception {
    final byte[] contents = getResourceBytes(new ClassPathResource("ec.pkcs8.enc.key"));
    assertThrows(KeyException.class, () -> KeyUtils.decodePrivateKey(contents, "bad".toCharArray()));
    try (final InputStream is = new ByteArrayInputStream("not a key".getBytes())) {
      assertThrows(KeyException.class, () -> KeyUtils.decodePrivateKey(is));
    }
  }

  @Test
  void testIoError() throws Exception {
    try (final InputStream is = Mockito.mock(InputStream.class)) {
      Mockito.when(is.readAllBytes()).thenThrow(new IOException("test"));
      Exception e = assertThrows(KeyException.class, () -> KeyUtils.decodePrivateKey(is));
      assertTrue(e.getCause() instanceof IOException);
      e = assertThrows(KeyException.class, () -> KeyUtils.decodePrivateKey(is, "bad".toCharArray()));
      assertTrue(e.getCause() instanceof IOException);
    }
  }

  @Test
  void testIoError2() throws Exception {
    try (final InputStream is = Mockito.mock(InputStream.class)) {
      Mockito.when(is.readAllBytes()).thenThrow(new IOException("test"));
      final Exception e = assertThrows(KeyException.class, () -> KeyUtils.decodePublicKey(is));
      assertTrue(e.getCause() instanceof IOException);
    }
  }

  private static byte[] getResourceBytes(final Resource resource) throws IOException {
    return resource.getInputStream().readAllBytes();
  }
}
