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

import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import se.swedenconnect.security.credential.factory.KeyStoreFactory;

import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test cases for BasicCredential.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class BasicCredentialTest {

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
  }

  @Test
  void testDefaultNameCertSet() {
    final BasicCredential cred = new BasicCredential(this.cert, this.privateKey);

    assertEquals(this.cert.getSubjectX500Principal().getName(), cred.getName());
  }

  @Test
  void testDefaultNamePubKeySet() {
    final BasicCredential cred = new BasicCredential(this.cert.getPublicKey(), this.privateKey);
    assertTrue(cred.getName().startsWith("RSA-"));
  }

}
