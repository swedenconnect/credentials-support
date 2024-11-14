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
 * Test cases for PrivateKeyUtils.
 *
 * @author Martin Lindström
 */
class PrivateKeyUtilsTest {

  @BeforeAll
  static void setUp() {
    if (Security.getProvider("BC") == null) {
      Security.insertProviderAt(new BouncyCastleProvider(), 2);
    }
  }

  @Test
  void testIsInlinedPem() throws Exception {
    assertFalse(PrivateKeyUtils.isInlinedPem("classpath:file.key"));
    assertTrue(PrivateKeyUtils.isInlinedPem(new String(getResourceBytes(new ClassPathResource("rsa1.openssl.key")))));
  }

  @Test
  void testOpenSslRsaKey() throws Exception {
    final byte[] contents = getResourceBytes(new ClassPathResource("rsa1.openssl.key"));
    try (final InputStream is = new ByteArrayInputStream(contents)) {
      assertNotNull(PrivateKeyUtils.decodePrivateKey(is));
    }
    assertNotNull(PrivateKeyUtils.decodePrivateKey(contents));
  }

  @Test
  void testEncryptedOpenSslRsaKey() throws Exception {
    final byte[] contents = getResourceBytes(new ClassPathResource("rsa1.openssl.enc.key"));
    try (final InputStream is = new ByteArrayInputStream(contents)) {
      assertNotNull(PrivateKeyUtils.decodePrivateKey(is, "secret".toCharArray()));
    }
    assertNotNull(PrivateKeyUtils.decodePrivateKey(contents, "secret".toCharArray()));
  }

  @Test
  void testPkcs8RsaKey() throws Exception {
    final byte[] contents = getResourceBytes(new ClassPathResource("rsa1.pkcs8.key"));
    try (final InputStream is = new ByteArrayInputStream(contents)) {
      assertNotNull(PrivateKeyUtils.decodePrivateKey(is));
    }
    assertNotNull(PrivateKeyUtils.decodePrivateKey(contents));
  }

  @Test
  void testEncryptedPkcs8RsaKey() throws Exception {
    final byte[] contents = getResourceBytes(new ClassPathResource("rsa1.pkcs8.enc.key"));
    try (final InputStream is = new ByteArrayInputStream(contents)) {
      assertNotNull(PrivateKeyUtils.decodePrivateKey(is, "secret".toCharArray()));
    }
    assertNotNull(PrivateKeyUtils.decodePrivateKey(contents, "secret".toCharArray()));
  }

  @Test
  void testOpenSslEcKey() throws Exception {
    final byte[] contents = getResourceBytes(new ClassPathResource("ec.openssl.key"));
    try (final InputStream is = new ByteArrayInputStream(contents)) {
      assertNotNull(PrivateKeyUtils.decodePrivateKey(is));
    }
    assertNotNull(PrivateKeyUtils.decodePrivateKey(contents));
  }

  @Test
  void testEncryptedOpenSslEcKey() throws Exception {
    final byte[] contents = getResourceBytes(new ClassPathResource("ec.openssl.enc.key"));
    try (final InputStream is = new ByteArrayInputStream(contents)) {
      assertNotNull(PrivateKeyUtils.decodePrivateKey(is, "secret".toCharArray()));
    }
    assertNotNull(PrivateKeyUtils.decodePrivateKey(contents, "secret".toCharArray()));
  }

  @Test
  void testPkcs8EcKey() throws Exception {
    final byte[] contents = getResourceBytes(new ClassPathResource("ec.pkcs8.key"));
    try (final InputStream is = new ByteArrayInputStream(contents)) {
      assertNotNull(PrivateKeyUtils.decodePrivateKey(is));
    }
    assertNotNull(PrivateKeyUtils.decodePrivateKey(contents));
  }

  @Test
  void testEncryptedPkcs8EcKey() throws Exception {
    final byte[] contents = getResourceBytes(new ClassPathResource("ec.pkcs8.enc.key"));
    try (final InputStream is = new ByteArrayInputStream(contents)) {
      assertNotNull(PrivateKeyUtils.decodePrivateKey(is, "secret".toCharArray()));
    }
    assertNotNull(PrivateKeyUtils.decodePrivateKey(contents, "secret".toCharArray()));
  }

  @Test
  void testEncodingError() throws Exception {
    assertThrows(KeyException.class, () -> PrivateKeyUtils.decodePrivateKey("NOT A KEY".getBytes()));
    try (final InputStream is = new ByteArrayInputStream("not a key".getBytes())) {
      assertThrows(KeyException.class, () -> PrivateKeyUtils.decodePrivateKey(is));
    }
  }

  @Test
  void testBadPassword() throws Exception {
    final byte[] contents = getResourceBytes(new ClassPathResource("ec.pkcs8.enc.key"));
    assertThrows(KeyException.class, () -> PrivateKeyUtils.decodePrivateKey(contents, "bad".toCharArray()));
    try (final InputStream is = new ByteArrayInputStream("not a key".getBytes())) {
      assertThrows(KeyException.class, () -> PrivateKeyUtils.decodePrivateKey(is));
    }
  }

  @Test
  void testIoError() throws Exception {
    try (final InputStream is = Mockito.mock(InputStream.class)) {
      Mockito.when(is.readAllBytes()).thenThrow(new IOException("test"));
      Exception e = assertThrows(KeyException.class, () -> PrivateKeyUtils.decodePrivateKey(is));
      assertTrue(e.getCause() instanceof IOException);
      e = assertThrows(KeyException.class, () -> PrivateKeyUtils.decodePrivateKey(is, "bad".toCharArray()));
      assertTrue(e.getCause() instanceof IOException);
    }

  }

  private static byte[] getResourceBytes(final Resource resource) throws IOException {
    return resource.getInputStream().readAllBytes();
  }
}
