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
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

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

  @Test
  void testLifecycleGroups() {
    final Instant t1 = Instant.parse("2026-01-01T00:00:00Z");
    final Instant t2 = Instant.parse("2026-06-01T00:00:00Z");
    final Instant t3 = Instant.parse("2026-09-01T00:00:00Z");

    final PkiCredential old = this.getCredential("rsa");
    old.getMetadata().setActiveTo(t2);
    final PkiCredential current = this.getCredential("rsa2");
    current.getMetadata().setActiveFrom(t1);
    final PkiCredential next = this.getCredential("ec");
    next.getMetadata().setActiveFrom(t3);
    final PkiCredential revoked = this.getCredential("ec2");
    revoked.getMetadata().setRevokedAt(t1);

    final AtomicReference<Instant> now = new AtomicReference<>(t2.plusSeconds(1));
    final PkiCredentialCollection collection =
        new PkiCredentialCollection(List.of(old, current, next, revoked), this.clock(now));

    Assertions.assertEquals(List.of(current), collection.getActiveCredentials());
    Assertions.assertEquals(List.of(next), collection.getNotYetActiveCredentials());
    Assertions.assertEquals(List.of(old, revoked), collection.getNoLongerActiveCredentials());
    Assertions.assertEquals(List.of(current, next), collection.getCredentialsToPublish());

    now.set(t3);
    Assertions.assertEquals(List.of(current, next), collection.getActiveCredentials());
    Assertions.assertTrue(collection.getNotYetActiveCredentials().isEmpty());

    // Before the revocation time, the revoked credential is active
    now.set(t1.minusSeconds(1));
    Assertions.assertEquals(List.of(old, revoked), collection.getActiveCredentials());
    Assertions.assertEquals(List.of(current, next), collection.getNotYetActiveCredentials());
  }

  @Test
  void testRevokedIsNotNotYetActive() {
    final Instant now = Instant.parse("2026-01-01T00:00:00Z");
    final PkiCredential credential = this.getCredential("rsa");
    credential.getMetadata().setActiveFrom(now.plusSeconds(10));
    credential.getMetadata().setRevokedAt(now.minusSeconds(10));

    Assertions.assertFalse(PkiCredentialCollection.isNotYetActiveAt(now).test(credential));
    Assertions.assertFalse(PkiCredentialCollection.isActiveAt(now).test(credential));
    Assertions.assertTrue(PkiCredentialCollection.isNoLongerActiveAt(now).test(credential));
    Assertions.assertTrue(PkiCredentialCollection.isRevokedAt(now).test(credential));
  }

  @Test
  void testSigningRuleLatestActiveFrom() {
    final Instant t1 = Instant.parse("2026-01-01T00:00:00Z");
    final Instant t2 = Instant.parse("2026-06-01T00:00:00Z");

    final PkiCredential noTimes = this.getCredential("rsa");
    noTimes.getMetadata().setUsage(PkiCredential.Metadata.USAGE_SIGNING);
    final PkiCredential a = this.getCredential("rsa2");
    a.getMetadata().setUsage(PkiCredential.Metadata.USAGE_SIGNING);
    a.getMetadata().setActiveFrom(t1);
    final PkiCredential b = this.getCredential("ec");
    b.getMetadata().setUsage(PkiCredential.Metadata.USAGE_SIGNING);
    b.getMetadata().setActiveFrom(t2);

    final AtomicReference<Instant> now = new AtomicReference<>(t1.minusSeconds(1));
    final PkiCredentialCollection collection =
        new PkiCredentialCollection(List.of(b, noTimes, a), this.clock(now));

    Assertions.assertEquals("rsa", collection.getCredentialForSigning().getName());
    now.set(t1);
    Assertions.assertEquals("rsa2", collection.getCredentialForSigning().getName());
    now.set(t2);
    Assertions.assertEquals("ec", collection.getCredentialForSigning().getName());

    // Filter
    Assertions.assertEquals("rsa2", collection.getCredentialForSigning(PkiCredentialCollection.isRsa).getName());
    Assertions.assertNull(collection.getCredentialForSigning(c -> false));

    // Equal times - list order decides
    noTimes.getMetadata().setActiveFrom(t2);
    Assertions.assertEquals("ec", collection.getCredentialForSigning().getName());
  }

  @Test
  void testSigningFilterAppliesToUnspecifiedUsage() {
    final PkiCredential signing = this.getCredential("rsa");
    signing.getMetadata().setUsage(PkiCredential.Metadata.USAGE_SIGNING);
    final PkiCredential unspecified = this.getCredential("ec");

    final PkiCredentialCollection collection = new PkiCredentialCollection(List.of(signing, unspecified));
    Assertions.assertEquals("rsa", collection.getCredentialForSigning().getName());
    Assertions.assertEquals("ec", collection.getCredentialForSigning(PkiCredentialCollection.isEc).getName());
  }

  @Test
  void testEncryptionWithFilterAndRevocation() {
    final Instant now = Instant.parse("2026-06-01T00:00:00Z");
    final PkiCredential rsa = this.getCredential("rsa");
    rsa.getMetadata().setUsage(PkiCredential.Metadata.USAGE_ENCRYPTION);
    rsa.getMetadata().setActiveFrom(now.minusSeconds(100));
    final PkiCredential rsa2 = this.getCredential("rsa2");
    rsa2.getMetadata().setUsage(PkiCredential.Metadata.USAGE_ENCRYPTION);
    rsa2.getMetadata().setActiveFrom(now.minusSeconds(10));
    final PkiCredential ec = this.getCredential("ec");
    ec.getMetadata().setUsage(PkiCredential.Metadata.USAGE_ENCRYPTION);
    ec.getMetadata().setActiveTo(now.minusSeconds(10));
    final PkiCredential ec2 = this.getCredential("ec2");
    ec2.getMetadata().setUsage(PkiCredential.Metadata.USAGE_ENCRYPTION);
    ec2.getMetadata().setRevokedAt(now.minusSeconds(10));

    final PkiCredentialCollection collection =
        new PkiCredentialCollection(List.of(rsa, rsa2, ec, ec2), Clock.fixed(now, ZoneOffset.UTC));

    final List<PkiCredential> c1 = collection.getCredentialsForEncryption();
    Assertions.assertEquals(List.of(rsa2, rsa, ec), c1);

    final List<PkiCredential> c2 = collection.getCredentialsForEncryption(PkiCredentialCollection.isEc);
    // No active EC encryption credential, but the old one is kept for decryption
    Assertions.assertEquals(List.of(ec), c2);

    final List<PkiCredential> c3 = collection.getCredentialsForEncryption(c -> c != rsa2);
    Assertions.assertEquals(List.of(rsa, ec), c3);
  }

  @Test
  void testConcurrentModificationWhileReading() {
    final PkiCredentialCollection collection = new PkiCredentialCollection(
        List.of(this.getCredential("rsa"), this.getCredential("ec")));
    for (final PkiCredential c : collection.getCredentials()) {
      collection.addCredential(this.getCredential("ec2"));
      collection.removeCredentials(x -> x == c);
    }
    Assertions.assertEquals(2, collection.getCredentials().size());
  }

  private Clock clock(final AtomicReference<Instant> now) {
    return new Clock() {
      @Override
      public java.time.ZoneId getZone() {
        return ZoneOffset.UTC;
      }

      @Override
      public Clock withZone(final java.time.ZoneId zone) {
        return this;
      }

      @Override
      public Instant instant() {
        return now.get();
      }
    };
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
