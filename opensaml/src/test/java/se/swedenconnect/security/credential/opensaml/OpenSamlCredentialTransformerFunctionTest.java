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
package se.swedenconnect.security.credential.opensaml;

import org.cryptacular.io.ClassPathResource;
import org.cryptacular.io.Resource;
import org.junit.jupiter.api.Test;
import org.opensaml.security.x509.X509Credential;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.KeyStoreFactory;

import java.io.InputStream;
import java.security.KeyStore;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Test cases for OpenSamlCredentialTransformerFunction.
 *
 * @author Martin Lindström
 */
class OpenSamlCredentialTransformerFunctionTest {

  private final KeyStore keyStore;

  public OpenSamlCredentialTransformerFunctionTest() throws Exception {
    final Resource resource = new ClassPathResource("rsa1.jks");
    try (final InputStream inputStream = resource.getInputStream()) {
      this.keyStore = KeyStoreFactory.loadKeyStore(inputStream, "secret".toCharArray(), null, null);
    }
  }

  @Test
  public void testTransformCredential() throws Exception {
    final PkiCredential cred = new KeyStoreCredential(this.keyStore, "test", "secret".toCharArray());

    final Function<PkiCredential, X509Credential> transformer = new OpenSamlCredentialTransformerFunction();
    final X509Credential samlCredential = transformer.apply(cred);
    assertNotNull(samlCredential);
  }

  @Test
  public void testTransformCredentialWithEntityId() throws Exception {
    final PkiCredential cred = new KeyStoreCredential(this.keyStore, "test", "secret".toCharArray());
    cred.getMetadata().getProperties().put(OpenSamlMetadataProperties.ENTITY_ID_PROPERTY, "https://www.example.com");

    final Function<PkiCredential, X509Credential> transformer = new OpenSamlCredentialTransformerFunction();
    final X509Credential samlCredential = transformer.apply(cred);
    assertNotNull(samlCredential);
    assertEquals("https://www.example.com", samlCredential.getEntityId());
  }

  @Test
  public void testTransformCredentialWithCustomEntityId() throws Exception {
    final PkiCredential cred = new KeyStoreCredential(this.keyStore, "test", "secret".toCharArray());

    final OpenSamlCredentialTransformerFunction transformer = new OpenSamlCredentialTransformerFunction();
    transformer.setEntityIdFunction(c -> "https://www.acme.com");
    final X509Credential samlCredential = transformer.apply(cred);
    assertNotNull(samlCredential);
    assertEquals("https://www.acme.com", samlCredential.getEntityId());
  }
}
