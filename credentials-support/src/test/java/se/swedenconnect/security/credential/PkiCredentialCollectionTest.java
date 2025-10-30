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
package se.swedenconnect.security.credential;

import org.cryptacular.io.ClassPathResource;
import org.cryptacular.io.Resource;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import se.swedenconnect.security.credential.factory.KeyStoreFactory;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.time.Instant;
import java.util.List;

/**
 * Test cases for {@link PkiCredentialCollection}.
 *
 * @author Martin Lindström
 */
public class PkiCredentialCollectionTest {

  private final KeyStore keyStore;

  public PkiCredentialCollectionTest() throws Exception {
    final Resource resource = new ClassPathResource("keys.jks");
    try (final InputStream inputStream = resource.getInputStream()) {
      this.keyStore = KeyStoreFactory.loadKeyStore(inputStream, "secret".toCharArray(), null, null);
    }
  }

  @Test
  void testGetAll() {
    final PkiCredentialCollection collection = new PkiCredentialCollection(
        List.of(this.getCredential("rsa"), this.getCredential("ec")));

    final List<PkiCredential> creds = collection.getCredentials();
    Assertions.assertTrue(creds.size() == 2);

    // Assert that the list is unmodifiable ...
    Assertions.assertThrows(UnsupportedOperationException.class, () -> creds.add(this.getCredential("ec2")));
  }

  @Test
  void testGetCredential() {
    final PkiCredentialCollection collection = new PkiCredentialCollection(
        List.of(this.getCredential("rsa"), this.getCredential("ec")));

    Assertions.assertEquals("rsa", collection.getCredential(c -> true).getName());
    Assertions.assertNull(collection.getCredential(c -> false));
  }

  @Test
  void testGetCredentials() {
    final PkiCredentialCollection collection = new PkiCredentialCollection(
        List.of(this.getCredential("rsa"), this.getCredential("ec")));

    final List<PkiCredential> creds = collection.getCredentials(c -> true);
    Assertions.assertTrue(creds.size() == 2);
    // Assert that the list is unmodifiable ...
    Assertions.assertThrows(UnsupportedOperationException.class, () -> creds.add(this.getCredential("ec2")));

    Assertions.assertTrue(collection.getCredentials(c -> false).isEmpty());
  }

  @Test
  void testAddCredential() {
    final PkiCredentialCollection collection = new PkiCredentialCollection(
        List.of(this.getCredential("rsa"), this.getCredential("ec")));

    collection.addCredential(this.getCredential("ec2"));
    Assertions.assertTrue(collection.getCredentials().size() == 3);
  }

  @Test
  void testRemoveCredentials() {
    final PkiCredentialCollection collection = new PkiCredentialCollection(
        List.of(this.getCredential("rsa"), this.getCredential("rsa2"), this.getCredential("ec")));

    final List<PkiCredential> removed =
        collection.removeCredentials(c -> "rsa".equals(c.getName()) || "ec".equals(c.getName()));

    Assertions.assertTrue(removed.size() == 2);
    Assertions.assertEquals("rsa", removed.get(0).getName());
    Assertions.assertEquals("ec", removed.get(1).getName());
    Assertions.assertTrue(collection.getCredentials().size() == 1);
    Assertions.assertNotNull(collection.getCredential(c -> "rsa2".equals(c.getName())));
  }

  @Test
  void testIsRsa() {
    final PkiCredentialCollection collection = new PkiCredentialCollection(
        List.of(this.getCredential("rsa"), this.getCredential("rsa2"), this.getCredential("ec")));

    final List<PkiCredential> creds = collection.getCredentials(PkiCredentialCollection.isRsa);
    Assertions.assertTrue(creds.size() == 2);
    Assertions.assertEquals("rsa", creds.get(0).getName());
    Assertions.assertEquals("rsa2", creds.get(1).getName());
  }

  @Test
  void testIsEc() {
    final PkiCredentialCollection collection = new PkiCredentialCollection(
        List.of(this.getCredential("rsa"), this.getCredential("rsa2"), this.getCredential("ec")));

    final List<PkiCredential> creds = collection.getCredentials(PkiCredentialCollection.isEc);
    Assertions.assertTrue(creds.size() == 1);
    Assertions.assertEquals("ec", creds.get(0).getName());
  }

  @Test
  void testIsHardwareCredential() {
    final PkiCredential hardware = Mockito.mock(PkiCredential.class);
    Mockito.when(hardware.getName()).thenReturn("hardware");
    Mockito.when(hardware.isHardwareCredential()).thenReturn(true);

    Assertions.assertTrue(PkiCredentialCollection.isHardwareCredential.test(hardware));
    Assertions.assertFalse(PkiCredentialCollection.isHardwareCredential.test(this.getCredential("rsa")));
  }

  @Test
  void testKeyId() {
    final PkiCredential credential = this.getCredential("rsa");
    credential.getMetadata().setKeyId("1234");

    Assertions.assertTrue(PkiCredentialCollection.keyId("1234").test(credential));
    Assertions.assertFalse(PkiCredentialCollection.keyId("5678").test(credential));
  }

  @Test
  void testUsage() {
    final PkiCredential credential = this.getCredential("rsa");

    Assertions.assertFalse(PkiCredentialCollection.usage("signature").test(credential));

    credential.getMetadata().setUsage("signature");

    Assertions.assertTrue(PkiCredentialCollection.usage("signature").test(credential));
    Assertions.assertTrue(PkiCredentialCollection.usage("SIGNATURE").test(credential));
    Assertions.assertFalse(PkiCredentialCollection.usage("encryption").test(credential));
  }

  @Test
  void testSignatureUsage() {
    final PkiCredential credential = this.getCredential("rsa");

    Assertions.assertFalse(PkiCredentialCollection.signatureUsage.test(credential));

    credential.getMetadata().setUsage(PkiCredential.Metadata.USAGE_ENCRYPTION);
    Assertions.assertFalse(PkiCredentialCollection.signatureUsage.test(credential));

    credential.getMetadata().setUsage(PkiCredential.Metadata.USAGE_SIGNING);

    Assertions.assertTrue(PkiCredentialCollection.signatureUsage.test(credential));
  }

  @Test
  void testEncryptionUsage() {
    final PkiCredential credential = this.getCredential("rsa");

    Assertions.assertFalse(PkiCredentialCollection.encryptionUsage.test(credential));

    credential.getMetadata().setUsage(PkiCredential.Metadata.USAGE_SIGNING);
    Assertions.assertFalse(PkiCredentialCollection.encryptionUsage.test(credential));

    credential.getMetadata().setUsage(PkiCredential.Metadata.USAGE_ENCRYPTION);

    Assertions.assertTrue(PkiCredentialCollection.encryptionUsage.test(credential));
  }

  @Test
  void testUnspecifiedUsage() {
    final PkiCredential credential = this.getCredential("rsa");

    Assertions.assertTrue(PkiCredentialCollection.unspecifiedUsage.test(credential));

    credential.getMetadata().setUsage(PkiCredential.Metadata.USAGE_SIGNING);
    Assertions.assertFalse(PkiCredentialCollection.unspecifiedUsage.test(credential));

    credential.getMetadata().setUsage(null);

    Assertions.assertTrue(PkiCredentialCollection.unspecifiedUsage.test(credential));
  }

  @Test
  void testInActive() {
    final Instant now = Instant.now();

    final PkiCredential credential = this.getCredential("rsa");

    Assertions.assertTrue(PkiCredentialCollection.isActive.test(credential));

    credential.getMetadata().setActiveTo(now.minusSeconds(10));
    Assertions.assertFalse(PkiCredentialCollection.isActive.test(credential));

    credential.getMetadata().setActiveTo(now.plusSeconds(10));
    credential.getMetadata().setActiveFrom(now.plusSeconds(5));
    Assertions.assertFalse(PkiCredentialCollection.isActive.test(credential));

    credential.getMetadata().setActiveFrom(now.minusSeconds(5));
    Assertions.assertTrue(PkiCredentialCollection.isActive.test(credential));
  }

  @Test
  void testNoLongerActive() {
    final Instant now = Instant.now();

    final PkiCredential credential = this.getCredential("rsa");

    Assertions.assertFalse(PkiCredentialCollection.noLongerActive.test(credential));

    credential.getMetadata().setActiveTo(now.minusSeconds(10));
    Assertions.assertTrue(PkiCredentialCollection.noLongerActive.test(credential));

    credential.getMetadata().setActiveTo(now.plusSeconds(10));
    Assertions.assertFalse(PkiCredentialCollection.noLongerActive.test(credential));
  }

  @Test
  void testIsNotYetActive() {
    final Instant now = Instant.now();

    final PkiCredential credential = this.getCredential("rsa");

    Assertions.assertFalse(PkiCredentialCollection.isNotYetActive.test(credential));

    credential.getMetadata().setActiveFrom(now.plusSeconds(10));
    Assertions.assertTrue(PkiCredentialCollection.isNotYetActive.test(credential));

    credential.getMetadata().setActiveFrom(now.minusSeconds(10));
    Assertions.assertFalse(PkiCredentialCollection.isNotYetActive.test(credential));
  }

  @Test
  void testForFutureSigning() {
    final Instant now = Instant.now();

    final PkiCredential credential = this.getCredential("rsa");

    Assertions.assertFalse(PkiCredentialCollection.forFutureSigning.test(credential));

    credential.getMetadata().setActiveFrom(now.plusSeconds(10));
    Assertions.assertFalse(PkiCredentialCollection.forFutureSigning.test(credential));
    credential.getMetadata().setUsage(PkiCredential.Metadata.USAGE_SIGNING);
    Assertions.assertTrue(PkiCredentialCollection.forFutureSigning.test(credential));

    credential.getMetadata().setActiveFrom(now.minusSeconds(10));
    Assertions.assertFalse(PkiCredentialCollection.forFutureSigning.test(credential));
  }

  @Test
  void testGetCredentialForSigning() {
    final PkiCredential rsa = this.getCredential("rsa");
    final PkiCredential rsa2 = this.getCredential("rsa2");
    final PkiCredential ec = this.getCredential("ec");
    final PkiCredential ec2 = this.getCredential("ec2");
    final PkiCredentialCollection collection = new PkiCredentialCollection(List.of(rsa, rsa2, ec, ec2));

    Assertions.assertEquals("rsa", collection.getCredentialForSigning().getName());

    rsa2.getMetadata().setUsage(PkiCredential.Metadata.USAGE_SIGNING);
    Assertions.assertEquals("rsa2", collection.getCredentialForSigning().getName());

    rsa.getMetadata().setUsage(PkiCredential.Metadata.USAGE_ENCRYPTION);
    rsa2.getMetadata().setActiveTo(Instant.now().minusSeconds(10));
    Assertions.assertEquals("ec", collection.getCredentialForSigning().getName());

    ec.getMetadata().setActiveFrom(Instant.now().plusSeconds(10));
    Assertions.assertEquals("ec2", collection.getCredentialForSigning().getName());

    ec2.getMetadata().setUsage(PkiCredential.Metadata.USAGE_ENCRYPTION);
    Assertions.assertNull(collection.getCredentialForSigning());
  }

  @Test
  void getCredentialsForEncryption() {
    final PkiCredential rsa = this.getCredential("rsa");
    final PkiCredential rsa2 = this.getCredential("rsa2");
    final PkiCredential ec = this.getCredential("ec");
    final PkiCredential ec2 = this.getCredential("ec2");
    final PkiCredentialCollection collection = new PkiCredentialCollection(List.of(rsa, rsa2, ec, ec2));

    Assertions.assertTrue(collection.getCredentialsForEncryption().size() == 4);

    rsa.getMetadata().setUsage(PkiCredential.Metadata.USAGE_ENCRYPTION);
    rsa2.getMetadata().setUsage(PkiCredential.Metadata.USAGE_ENCRYPTION);
    rsa2.getMetadata().setActiveTo(Instant.now().minusSeconds(10));

    final List<PkiCredential> c1 = collection.getCredentialsForEncryption();
    Assertions.assertTrue(c1.size() == 2);
    Assertions.assertEquals("rsa", c1.get(0).getName());
    Assertions.assertEquals("rsa2", c1.get(1).getName());

    rsa2.getMetadata().setUsage(PkiCredential.Metadata.USAGE_SIGNING);
    final List<PkiCredential> c2 = collection.getCredentialsForEncryption();
    Assertions.assertTrue(c2.size() == 1);
    Assertions.assertEquals("rsa", c2.get(0).getName());

    rsa.getMetadata().setUsage(PkiCredential.Metadata.USAGE_SIGNING);
    rsa2.getMetadata().setUsage(PkiCredential.Metadata.USAGE_ENCRYPTION);
    ec2.getMetadata().setActiveTo(Instant.now().minusSeconds(10));
    final List<PkiCredential> c3 = collection.getCredentialsForEncryption();
    Assertions.assertTrue(c3.size() == 2);
    Assertions.assertEquals("ec", c3.get(0).getName());
    Assertions.assertEquals("rsa2", c3.get(1).getName());

    rsa2.getMetadata().setUsage(PkiCredential.Metadata.USAGE_SIGNING);
    final List<PkiCredential> c4 = collection.getCredentialsForEncryption();
    Assertions.assertTrue(c4.size() == 2);
    Assertions.assertEquals("ec", c4.get(0).getName());
    Assertions.assertEquals("ec2", c4.get(1).getName());
  }

  private PkiCredential getCredential(final String alias) {
    try {
      final KeyStoreCredential cred = new KeyStoreCredential(this.keyStore, alias, "secret".toCharArray());
      cred.setName(alias);
      return cred;
    }
    catch (final KeyStoreException e) {
      throw new RuntimeException(e);
    }
  }
}
