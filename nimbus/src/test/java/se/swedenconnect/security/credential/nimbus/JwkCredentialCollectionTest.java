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
package se.swedenconnect.security.credential.nimbus;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyRevocation;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.cryptacular.io.ClassPathResource;
import org.junit.jupiter.api.Test;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.PkiCredentialCollection;
import se.swedenconnect.security.credential.factory.KeyStoreFactory;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test cases for {@link JwkCredentialCollection}.
 *
 * @author Martin Lindström
 */
class JwkCredentialCollectionTest {

  private static final char[] PW = "secret".toCharArray();
  private static final Instant NOW = Instant.parse("2026-06-01T00:00:00Z");

  private final KeyStore keyStore;

  public JwkCredentialCollectionTest() throws Exception {
    try (final InputStream is = new ClassPathResource("test-1.jks").getInputStream()) {
      this.keyStore = KeyStoreFactory.loadKeyStore(is, PW, null, null);
    }
  }

  @Test
  void testJwkSets() throws Exception {
    final PkiCredential old = this.credential("test1", "old");
    old.getMetadata().setActiveTo(NOW.minusSeconds(10));
    final PkiCredential current = this.credential("test3", "current");
    final PkiCredential next = this.credential("test4", "next");
    next.getMetadata().setActiveFrom(NOW.plusSeconds(100));
    final PkiCredential revoked = this.credential("test1", "revoked");
    revoked.getMetadata().setRevokedAt(NOW.minusSeconds(100));
    revoked.getMetadata().setRevocationReason("compromised");

    final JwkCredentialCollection jwks = this.collection(old, current, next, revoked);

    final JWKSet published = jwks.getJwkSet();
    assertEquals(List.of("current", "next"), published.getKeys().stream().map(JWK::getKeyID).toList());
    assertTrue(published.getKeys().stream().noneMatch(JWK::isPrivate));
    assertEquals(Date.from(NOW.plusSeconds(100)), published.getKeyByKeyId("next").getNotBeforeTime());

    final JWKSet noLongerActive = jwks.getNoLongerActiveJwkSet();
    assertEquals(List.of("old", "revoked"), noLongerActive.getKeys().stream().map(JWK::getKeyID).toList());
    assertNull(noLongerActive.getKeyByKeyId("old").getKeyRevocation());
    final KeyRevocation revocation = noLongerActive.getKeyByKeyId("revoked").getKeyRevocation();
    assertEquals(Date.from(NOW.minusSeconds(100)), revocation.getRevocationTime());
    assertEquals(KeyRevocation.Reason.COMPROMISED, revocation.getReason());
  }

  @Test
  void testSignDefaultAlgorithm() throws Exception {
    final PkiCredential rsa = this.credential("test1", "rsa");
    rsa.getMetadata().setActiveFrom(NOW.minusSeconds(100));
    final PkiCredential ec = this.credential("test4", "ec");
    ec.getMetadata().setActiveFrom(NOW.minusSeconds(10));

    final JwkCredentialCollection jwks = this.collection(rsa, ec);

    final SignedJWT jwt = jwks.sign(this.claims(), new JOSEObjectType("entity-statement+jwt"));
    assertEquals(JWSAlgorithm.ES256, jwt.getHeader().getAlgorithm());
    assertEquals("ec", jwt.getHeader().getKeyID());
    assertEquals("entity-statement+jwt", jwt.getHeader().getType().getType());
    assertTrue(jwt.verify(new ECDSAVerifier((ECPublicKey) ec.getPublicKey())));

    ec.getMetadata().setActiveTo(NOW.minusSeconds(1));
    final SignedJWT jwt2 = jwks.sign(this.claims(), null);
    assertEquals(JWSAlgorithm.RS256, jwt2.getHeader().getAlgorithm());
    assertEquals("rsa", jwt2.getHeader().getKeyID());
    assertNull(jwt2.getHeader().getType());
    assertTrue(jwt2.verify(new RSASSAVerifier((RSAPublicKey) rsa.getPublicKey())));
  }

  @Test
  void testSignJoseAlgorithm() throws Exception {
    final PkiCredential rsa = this.credential("test1", "rsa");
    JwkMetadataProperties.setJoseAlgorithm(rsa.getMetadata(), "PS512");

    final SignedJWT jwt = this.collection(rsa).sign(this.claims(), null);
    assertEquals(JWSAlgorithm.PS512, jwt.getHeader().getAlgorithm());
    assertTrue(jwt.verify(new RSASSAVerifier((RSAPublicKey) rsa.getPublicKey())));
  }

  @Test
  void testSignAllowedAlgorithms() throws Exception {
    final PkiCredential rsa = this.credential("test1", "rsa");
    rsa.getMetadata().setActiveFrom(NOW.minusSeconds(100));
    final PkiCredential ec = this.credential("test4", "ec");
    ec.getMetadata().setActiveFrom(NOW.minusSeconds(10));

    final JwkCredentialCollection jwks = this.collection(rsa, ec);

    // The EC key is newer, but only RSA algorithms are allowed. List order decides the algorithm.
    final SignedJWT jwt = jwks.sign(this.claims(), null, List.of(JWSAlgorithm.PS256, JWSAlgorithm.RS256));
    assertEquals(JWSAlgorithm.PS256, jwt.getHeader().getAlgorithm());
    assertEquals("rsa", jwt.getHeader().getKeyID());

    final SignedJWT jwt2 = jwks.sign(this.claims(), null, List.of(JWSAlgorithm.RS256, JWSAlgorithm.ES256));
    assertEquals(JWSAlgorithm.ES256, jwt2.getHeader().getAlgorithm());
    assertEquals("ec", jwt2.getHeader().getKeyID());

    assertThrows(JOSEException.class, () -> jwks.sign(this.claims(), null, List.of(JWSAlgorithm.ES384)));
    assertThrows(JOSEException.class, () -> jwks.sign(this.claims(), null, List.of()));

    // jose-alg restricts the key
    JwkMetadataProperties.setJoseAlgorithm(rsa.getMetadata(), "RS256");
    final SignedJWT jwt3 = jwks.sign(this.claims(), null, List.of(JWSAlgorithm.PS256, JWSAlgorithm.RS256));
    assertEquals(JWSAlgorithm.RS256, jwt3.getHeader().getAlgorithm());
    assertThrows(JOSEException.class, () -> jwks.sign(this.claims(), null, List.of(JWSAlgorithm.PS256)));
  }

  @Test
  void testSignHeaderCustomizer() throws Exception {
    final PkiCredential ec = this.credential("test4", "ec");

    final SignedJWT jwt = this.collection(ec).sign(this.claims(), JOSEObjectType.JWT, null,
        h -> h.keyID("other").customParam("trust_chain", List.of("a", "b")));
    assertEquals("ec", jwt.getHeader().getKeyID());
    assertEquals(JOSEObjectType.JWT, jwt.getHeader().getType());
    assertEquals(List.of("a", "b"), jwt.getHeader().getCustomParam("trust_chain"));
  }

  @Test
  void testNoSigningCredential() throws Exception {
    final PkiCredential ec = this.credential("test4", "ec");
    ec.getMetadata().setUsage(PkiCredential.Metadata.USAGE_ENCRYPTION);
    assertThrows(JOSEException.class, () -> this.collection(ec).sign(this.claims(), null));
  }

  @Test
  void testSupportsAlgorithm() throws Exception {
    final PkiCredential rsa = this.credential("test1", "rsa");
    final PkiCredential ec = this.credential("test4", "ec");

    assertTrue(JwkCredentialCollection.supportsAlgorithm(JWSAlgorithm.RS256).test(rsa));
    assertTrue(JwkCredentialCollection.supportsAlgorithm(JWSAlgorithm.PS384).test(rsa));
    assertFalse(JwkCredentialCollection.supportsAlgorithm(JWSAlgorithm.ES256).test(rsa));
    assertTrue(JwkCredentialCollection.supportsAlgorithm(JWSAlgorithm.ES256).test(ec));
    assertFalse(JwkCredentialCollection.supportsAlgorithm(JWSAlgorithm.ES384).test(ec));

    JwkMetadataProperties.setJoseAlgorithm(rsa.getMetadata(), "RS256");
    assertTrue(JwkCredentialCollection.supportsAlgorithm(JWSAlgorithm.RS256).test(rsa));
    assertFalse(JwkCredentialCollection.supportsAlgorithm(JWSAlgorithm.PS256).test(rsa));

    // jose-alg that does not fit the key type
    JwkMetadataProperties.setJoseAlgorithm(ec.getMetadata(), "RS256");
    assertFalse(JwkCredentialCollection.supportsAlgorithm(JWSAlgorithm.RS256).test(ec));
  }

  private JwkCredentialCollection collection(final PkiCredential... credentials) {
    return new JwkCredentialCollection(
        new PkiCredentialCollection(List.of(credentials), Clock.fixed(NOW, ZoneOffset.UTC)));
  }

  private JWTClaimsSet claims() {
    return new JWTClaimsSet.Builder().issuer("https://issuer.example.com").subject("sub").build();
  }

  private PkiCredential credential(final String alias, final String keyId) throws Exception {
    final KeyStoreCredential credential = new KeyStoreCredential(this.keyStore, alias, PW);
    credential.getMetadata().setKeyId(keyId);
    return credential;
  }

}
