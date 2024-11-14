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

import org.cryptacular.io.ClassPathResource;
import org.cryptacular.io.Resource;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test cases for X509Utils.
 *
 * @author Martin Lindström
 */
class X509UtilsTest {

  @Test
  void testIsInlinedPem() throws Exception {
    assertFalse(X509Utils.isInlinedPem("classpath:file.key"));
    assertTrue(X509Utils.isInlinedPem(new String(getResourceBytes(new ClassPathResource("rsa1.crt")))));
  }

  @Test
  void testDecodePem() throws Exception {
    final byte[] contents = getResourceBytes(new ClassPathResource("rsa1.crt"));
    assertNotNull(X509Utils.decodeCertificate(contents));
    try (final InputStream is = new ByteArrayInputStream(contents)) {
      assertNotNull(X509Utils.decodeCertificate(is));
    }
  }

  @Test
  void testDecodeDer() throws Exception {
    final byte[] contents = getResourceBytes(new ClassPathResource("rsa1-der.crt"));
    assertNotNull(X509Utils.decodeCertificate(contents));
    try (final InputStream is = new ByteArrayInputStream(contents)) {
      assertNotNull(X509Utils.decodeCertificate(is));
    }
  }

  @Test
  void testDecodeChain() throws Exception {
    final byte[] contents = getResourceBytes(new ClassPathResource("chain.pem"));
    List<X509Certificate> chain = X509Utils.decodeCertificateChain(contents);
    assertTrue(chain.size() == 2);
    try (final InputStream is = new ByteArrayInputStream(contents)) {
      chain = X509Utils.decodeCertificateChain(is);
      assertTrue(chain.size() == 2);
    }
  }

  @Test
  void testDecodingError() throws Exception {
    assertThrows(CertificateException.class, () -> X509Utils.decodeCertificate("bad".getBytes()));
    try (final InputStream is = new ByteArrayInputStream("bad".getBytes())) {
      assertThrows(CertificateException.class, () -> X509Utils.decodeCertificate(is));
    }
    assertThrows(CertificateException.class, () -> X509Utils.decodeCertificateChain("bad".getBytes()));
    try (final InputStream is = new ByteArrayInputStream("bad".getBytes())) {
      assertThrows(CertificateException.class, () -> X509Utils.decodeCertificateChain(is));
    }
  }

  @Test
  void testToLogString() throws Exception {
    final X509Certificate cert = X509Utils.decodeCertificate(getResourceBytes(new ClassPathResource("rsa1.crt")));
    final String s = X509Utils.toLogString(cert);
    assertTrue(s.contains("subject='"));
    assertTrue(s.contains("issuer='"));
    assertTrue(s.contains("serial-number='"));

    assertEquals("null", X509Utils.toLogString(null));
  }

  private static byte[] getResourceBytes(final Resource resource) throws IOException {
    return resource.getInputStream().readAllBytes();
  }
}
