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
package se.swedenconnect.security.credential.container;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.swedenconnect.security.credential.AbstractPkiCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.container.keytype.KeyGenType;

import java.security.Security;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Test cases for InMemoryPkiCredentialContainer.
 */
public class InMemoryPkiCredentialContainerTest {

  @BeforeAll
  static void init() {
    if (Security.getProvider("BC") == null) {
      Security.insertProviderAt(new BouncyCastleProvider(), 2);
    }
  }

  @Test
  public void testUsage() throws Exception {
    final InMemoryPkiCredentialContainer container = new InMemoryPkiCredentialContainer("BC");
    final String alias1 = container.generateCredential(KeyGenType.EC_P256);
    final String alias2 = container.generateCredential(KeyGenType.RSA_3072);

    final PkiCredential cred1 = container.getCredential(alias1);
    Assertions.assertNotNull(cred1);
    Assertions.assertNull(cred1.getCertificate());
    Assertions.assertTrue(cred1.getPublicKey().getAlgorithm().equals("EC"));

    final PkiCredential cred2 = container.getCredential(alias2);
    Assertions.assertNotNull(cred2);
    Assertions.assertTrue(cred2.getPublicKey().getAlgorithm().equals("RSA"));

    Assertions.assertTrue(container.getExpiryTime(alias1).isAfter(Instant.now()));
    Assertions.assertTrue(container.listCredentials().size() == 2);
    container.cleanup();
    Assertions.assertTrue(container.listCredentials().size() == 2);

    container.deleteCredential(alias2);
    Assertions.assertTrue(container.listCredentials().size() == 1);
    container.deleteCredential(alias1);
    Assertions.assertTrue(container.listCredentials().isEmpty());
  }

  @Test
  public void testDestroy() throws Exception {
    final InMemoryPkiCredentialContainer container = new InMemoryPkiCredentialContainer("BC");
    final String alias = container.generateCredential(KeyGenType.EC_P256);
    final PkiCredential cred = container.getCredential(alias);
    Assertions.assertTrue(container.listCredentials().size() == 1);
    cred.destroy();
    Assertions.assertTrue(container.listCredentials().isEmpty());

    // Ensure that multiple calls to destroy doesn't mess things up
    cred.destroy();
  }

  @Test
  public void testEternalValidity() throws Exception {
    final InMemoryPkiCredentialContainer container = new InMemoryPkiCredentialContainer(Security.getProvider("BC"));
    container.setKeyValidity(null);
    final String alias1 = container.generateCredential(KeyGenType.EC_P256);
    Assertions.assertNull(container.getExpiryTime(alias1));
  }

  @Test
  public void testNotFound() {
    final InMemoryPkiCredentialContainer container = new InMemoryPkiCredentialContainer("BC");
    assertThatThrownBy(() -> container.getCredential("not-found")).isInstanceOf(PkiCredentialContainerException.class)
        .hasMessageContaining("was not found");
  }

  @Test
  public void testCredentialName() throws Exception {
    final InMemoryPkiCredentialContainer container = new InMemoryPkiCredentialContainer("BC");
    final String alias = container.generateCredential(KeyGenType.EC_P256);
    final PkiCredential cred = container.getCredential(alias);
    Assertions.assertNotNull(cred);
    Assertions.assertEquals(alias, cred.getName());

    // Set name should not be allowed
    assertThatThrownBy(() -> ((AbstractPkiCredential) cred).setName("new-name")).isInstanceOf(
            IllegalArgumentException.class)
        .hasMessage("The credential name can not be set");
  }

}
