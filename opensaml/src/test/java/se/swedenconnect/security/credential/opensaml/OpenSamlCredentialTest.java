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
package se.swedenconnect.security.credential.opensaml;

import org.cryptacular.io.ClassPathResource;
import org.cryptacular.io.Resource;
import org.junit.jupiter.api.Test;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.KeyStoreFactory;

import java.io.InputStream;
import java.security.KeyStore;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test cases for X509Credential.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
class OpenSamlCredentialTest {

  private final KeyStore keyStore;

  public OpenSamlCredentialTest() throws Exception {
    final Resource resource = new ClassPathResource("rsa1.jks");
    try (final InputStream inputStream = resource.getInputStream()) {
      this.keyStore = KeyStoreFactory.loadKeyStore(inputStream, "secret".toCharArray(), null, null);
    }
  }

  @Test
  void testInitKeyAndCertificate() throws Exception {
    final PkiCredential _cred = new KeyStoreCredential(this.keyStore, "test", "secret".toCharArray());

    final OpenSamlCredential cred = new OpenSamlCredential(_cred.getCertificate(), _cred.getPrivateKey());
    assertNotNull(cred.getEntityCertificate());
    assertNotNull(cred.getPrivateKey());
    assertNotNull(cred.getPublicKey());
    assertNotNull(cred.getEntityCertificateChain());
    assertFalse(cred.isHardwareCredential());
  }

  @Test
  void testInitKeyPairCredential() throws Exception {
    final KeyStoreCredential _cred = new KeyStoreCredential(this.keyStore, "test", "secret".toCharArray());

    final OpenSamlCredential cred = new OpenSamlCredential(_cred);
    assertNotNull(cred.getEntityCertificate());
    assertNotNull(cred.getPrivateKey());
    assertNotNull(cred.getPublicKey());
    assertNotNull(cred.getEntityCertificateChain());
    assertFalse(cred.isHardwareCredential());
  }

  @Test
  void testMixedInit() {
    assertThrows(IllegalArgumentException.class, () -> {
      final PkiCredential _cred = new KeyStoreCredential(this.keyStore, "test", "secret".toCharArray());

      final OpenSamlCredential cred = new OpenSamlCredential(_cred);
      cred.setPrivateKey(_cred.getPrivateKey());
    });
  }

  @Test
  void testSetChain() throws Exception {
    final PkiCredential _cred = new KeyStoreCredential(this.keyStore, "test", "secret".toCharArray());

    final OpenSamlCredential cred = new OpenSamlCredential(_cred);
    assertTrue(cred.getEntityCertificateChain().size() == 1);
  }

  @Test
  void testGetChain() throws Exception {
    final PkiCredential _cred = new KeyStoreCredential(this.keyStore, "test", "secret".toCharArray());

    final OpenSamlCredential cred = new OpenSamlCredential(_cred);
    assertTrue(cred.getEntityCertificateChain().size() == 1);
  }

  @Test
  void testSetEntityCertificate() throws Exception {
    final PkiCredential _cred = new KeyStoreCredential(this.keyStore, "test", "secret".toCharArray());
    final OpenSamlCredential cred = new OpenSamlCredential(_cred);

    assertThrows(IllegalArgumentException.class, () -> cred.setEntityCertificate(_cred.getCertificate()));
    assertThrows(IllegalArgumentException.class, () -> cred.setEntityCertificateChain(List.of(_cred.getCertificate())));
  }

}
