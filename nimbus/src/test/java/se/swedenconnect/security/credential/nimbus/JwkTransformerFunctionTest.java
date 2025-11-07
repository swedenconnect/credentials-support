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
package se.swedenconnect.security.credential.nimbus;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import org.cryptacular.io.ClassPathResource;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.KeyStoreFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.io.UncheckedIOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.function.BiConsumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test cases for JwkTransformerFunction.
 *
 * @author Martin Lindström
 */
class JwkTransformerFunctionTest {

  private final static char[] PW = "secret".toCharArray();
  private final static String ALIAS_RSA = "test1";
  private final static String ALIAS_EC = "test4";

  private final KeyStore keyStore;
  private final PrivateKey rsaPrivateKey;
  private final X509Certificate rsaCert;
  private final PrivateKey ecPrivateKey;
  private final X509Certificate ecCert;

  public JwkTransformerFunctionTest() throws Exception {
    try (final InputStream is = new ClassPathResource("test-1.jks").getInputStream()) {
      this.keyStore = KeyStoreFactory.loadKeyStore(is, PW, null, null);
    }
    this.rsaCert = (X509Certificate) this.keyStore.getCertificate(ALIAS_RSA);
    this.rsaPrivateKey = (PrivateKey) this.keyStore.getKey(ALIAS_RSA, PW);
    this.ecCert = (X509Certificate) this.keyStore.getCertificate(ALIAS_EC);
    this.ecPrivateKey = (PrivateKey) this.keyStore.getKey(ALIAS_EC, PW);
  }

  @Test
  void testRsa() throws Exception {
    final PkiCredential credential = new KeyStoreCredential(this.keyStore, ALIAS_RSA, PW);

    final JwkTransformerFunction function = new JwkTransformerFunction();
    final JWK jwk = function.apply(credential);
    assertNotNull(jwk);

    assertEquals(KeyType.RSA, jwk.getKeyType());
    assertTrue(jwk.isPrivate());
    assertNotNull(jwk.getKeyStore());
    assertEquals(jwk.computeThumbprint().toString(), jwk.getKeyID());
    assertNotNull(jwk.getX509CertChain());
    assertNotNull(jwk.getX509CertSHA256Thumbprint());
    assertNotNull(jwk.getIssueTime());
    assertNotNull(jwk.getNotBeforeTime());
    assertNotNull(jwk.getExpirationTime());
  }

  @Test
  void testRsaKeyPair() {
    final PkiCredential credential = new BasicCredential(this.rsaCert.getPublicKey(), this.rsaPrivateKey);

    final JwkTransformerFunction function = JwkTransformerFunction.function();
    final JWK jwk = function.apply(credential);
    assertNotNull(jwk);

    assertEquals(KeyType.RSA, jwk.getKeyType());
    assertTrue(jwk.isPrivate());
    assertNull(jwk.getKeyStore());
    assertNotNull(jwk.getKeyID());
    assertNull(jwk.getX509CertChain());
    assertNull(jwk.getX509CertSHA256Thumbprint());
    assertNull(jwk.getIssueTime());
    assertNull(jwk.getNotBeforeTime());
    assertNull(jwk.getExpirationTime());
  }

  @Test
  void testEc() throws Exception {
    final PkiCredential credential = new KeyStoreCredential(this.keyStore, ALIAS_EC, PW);

    final JwkTransformerFunction function = new JwkTransformerFunction();
    final JWK jwk = function.apply(credential);
    assertNotNull(jwk);

    assertEquals(KeyType.EC, jwk.getKeyType());
    assertTrue(jwk.isPrivate());
    assertNotNull(jwk.getKeyStore());
    assertEquals(jwk.computeThumbprint().toString(), jwk.getKeyID());
  }

  @Test
  void testEcKeyPair() {
    final PkiCredential credential = new BasicCredential(this.ecCert.getPublicKey(), this.ecPrivateKey);

    final JwkTransformerFunction function = new JwkTransformerFunction();
    final JWK jwk = function.apply(credential);
    assertNotNull(jwk);

    assertEquals(KeyType.EC, jwk.getKeyType());
    assertTrue(jwk.isPrivate());
    assertNull(jwk.getKeyStore());
    assertNotNull(jwk.getKeyID());
    assertNull(jwk.getX509CertChain());
    assertNull(jwk.getX509CertSHA256Thumbprint());
    assertNull(jwk.getIssueTime());
    assertNull(jwk.getNotBeforeTime());
    assertNull(jwk.getExpirationTime());
  }

  @Test
  void testUnsupportedKeyType() throws Exception {
    final PkiCredential credential = new KeyStoreCredential(this.keyStore, "dsa", PW);
    final JwkTransformerFunction function = new JwkTransformerFunction();
    final IllegalArgumentException ex =
        assertThrows(IllegalArgumentException.class, () -> function.apply(credential));
    assertEquals("Unsupported key type: DSA", ex.getMessage());
  }

  @Test
  void testKeyId() throws Exception {
    final PkiCredential credential = new KeyStoreCredential(this.keyStore, ALIAS_RSA, PW);
    credential.getMetadata().getProperties().put(PkiCredential.Metadata.KEY_ID_PROPERTY, "12345");

    final JwkTransformerFunction function = new JwkTransformerFunction();
    final JWK jwk = function.apply(credential);
    assertNotNull(jwk);
    assertEquals("12345", jwk.getKeyID());
  }

  @Test
  void testKeyIdCustomFunction() throws Exception {
    final PkiCredential credential = new KeyStoreCredential(this.keyStore, ALIAS_RSA, PW);

    final JwkTransformerFunction function = JwkTransformerFunction.function().withKeyIdFunction(c -> "12345");
    final JWK jwk = function.apply(credential);
    assertNotNull(jwk);
    assertEquals("12345", jwk.getKeyID());
  }

  @Test
  void testKeyUse() throws Exception {
    final PkiCredential credential = new KeyStoreCredential(this.keyStore, ALIAS_RSA, PW);
    credential.getMetadata().getProperties().put(JwkMetadataProperties.KEY_USE_PROPERTY, KeyUse.SIGNATURE);

    final JwkTransformerFunction function = new JwkTransformerFunction();
    final JWK jwk = function.apply(credential);
    assertNotNull(jwk);
    assertEquals(KeyUse.SIGNATURE, jwk.getKeyUse());

    JwkMetadataProperties.setKeyUse(credential.getMetadata(), KeyUse.ENCRYPTION);
    final JWK jwk2 = function.apply(credential);
    assertNotNull(jwk2);
    assertEquals(KeyUse.ENCRYPTION, jwk2.getKeyUse());

    JwkMetadataProperties.setKeyUse(credential.getMetadata(), KeyUse.SIGNATURE.identifier());
    final JWK jwk3 = function.apply(credential);
    assertNotNull(jwk3);
    assertEquals(KeyUse.SIGNATURE, jwk3.getKeyUse());

    // Also picks up usage ...
    JwkMetadataProperties.setKeyUse(credential.getMetadata(), (String) null);
    credential.getMetadata().setUsage(PkiCredential.Metadata.USAGE_SIGNING);
    final JWK jwk4 = function.apply(credential);
    assertNotNull(jwk4);
    assertEquals(KeyUse.SIGNATURE, jwk4.getKeyUse());

    // If key-ops are set, no key-use is produced
    JwkMetadataProperties.setKeyUse(credential.getMetadata(), KeyUse.ENCRYPTION);
    JwkMetadataProperties.setKeyOps(credential.getMetadata(), Set.of(KeyOperation.DECRYPT, KeyOperation.ENCRYPT));
    final JWK jwk5 = function.apply(credential);
    assertNotNull(jwk5);
    assertNull(jwk5.getKeyUse());
  }

  @Test
  void testKeyUseCustomFunction() throws Exception {
    final PkiCredential credential = new KeyStoreCredential(this.keyStore, ALIAS_RSA, PW);
    credential.getMetadata().getProperties().put(JwkMetadataProperties.KEY_USE_PROPERTY, KeyUse.SIGNATURE);

    final JwkTransformerFunction function = JwkTransformerFunction.function()
        .withKeyUseFunction(keyUse -> KeyUse.ENCRYPTION);
    final JWK jwk = function.apply(credential);
    assertNotNull(jwk);
    assertEquals(KeyUse.ENCRYPTION, jwk.getKeyUse());
  }

  @Test
  void testKeyOperations() throws Exception {
    final PkiCredential credential = new KeyStoreCredential(this.keyStore, ALIAS_RSA, PW);
    credential.getMetadata().getProperties().put(JwkMetadataProperties.KEY_OPS_PROPERTY,
        Set.of(KeyOperation.DECRYPT, KeyOperation.ENCRYPT, KeyOperation.SIGN));

    final JwkTransformerFunction function = new JwkTransformerFunction();

    JWK jwk = function.apply(credential);
    assertNotNull(jwk);
    Set<KeyOperation> keyOps = jwk.getKeyOperations();
    assertTrue(keyOps.contains(KeyOperation.DECRYPT));
    assertTrue(keyOps.contains(KeyOperation.ENCRYPT));
    assertTrue(keyOps.contains(KeyOperation.SIGN));
    assertEquals(3, keyOps.size());

    JwkMetadataProperties.setKeyOps(credential.getMetadata(), List.of(KeyOperation.DECRYPT.identifier()));
    jwk = function.apply(credential);
    assertNotNull(jwk);
    keyOps = jwk.getKeyOperations();
    assertTrue(keyOps.contains(KeyOperation.DECRYPT));
    assertEquals(1, keyOps.size());

    JwkMetadataProperties.setKeyOps(credential.getMetadata(),
        Set.of(KeyOperation.DECRYPT, KeyOperation.ENCRYPT, KeyOperation.SIGN));
    jwk = function.apply(credential);
    assertNotNull(jwk);
    keyOps = jwk.getKeyOperations();
    assertTrue(keyOps.contains(KeyOperation.DECRYPT));
    assertTrue(keyOps.contains(KeyOperation.ENCRYPT));
    assertTrue(keyOps.contains(KeyOperation.SIGN));
    assertEquals(3, keyOps.size());

    final IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
        () -> JwkMetadataProperties.setKeyOps(credential.getMetadata(),
            List.of(KeyOperation.DECRYPT.identifier(), "unknown")));
    assertEquals("Invalid key operation(s): [decrypt, unknown]", ex.getMessage());
  }

  @Test
  void testKeyOperationsCustomFunction() throws Exception {
    final PkiCredential credential = new KeyStoreCredential(this.keyStore, ALIAS_RSA, PW);

    final JwkTransformerFunction function = JwkTransformerFunction.function()
        .withKeyOpsFunction(keyOps -> Set.of(KeyOperation.DECRYPT, KeyOperation.ENCRYPT, KeyOperation.SIGN));

    final JWK jwk = function.apply(credential);
    assertNotNull(jwk);
    final Set<KeyOperation> keyOps = jwk.getKeyOperations();
    assertTrue(keyOps.contains(KeyOperation.DECRYPT));
    assertTrue(keyOps.contains(KeyOperation.ENCRYPT));
    assertTrue(keyOps.contains(KeyOperation.SIGN));
    assertEquals(3, keyOps.size());
  }

  @Test
  void testAlgorithm() throws Exception {
    final PkiCredential credential = new KeyStoreCredential(this.keyStore, ALIAS_RSA, PW);
    credential.getMetadata().getProperties().put(JwkMetadataProperties.JOSE_ALGORITHM_PROPERTY, JWSAlgorithm.RS256);

    final JwkTransformerFunction function = new JwkTransformerFunction();

    JWK jwk = function.apply(credential);
    assertNotNull(jwk);
    assertEquals(JWSAlgorithm.RS256, jwk.getAlgorithm());

    JwkMetadataProperties.setJoseAlgorithm(credential.getMetadata(), JWSAlgorithm.RS256.getName());
    jwk = function.apply(credential);
    assertNotNull(jwk);
    assertEquals(JWSAlgorithm.RS256, jwk.getAlgorithm());
  }

  @Test
  void testAlgorithmCustomFunction() throws Exception {
    final PkiCredential credential = new KeyStoreCredential(this.keyStore, ALIAS_RSA, PW);

    final JwkTransformerFunction function = JwkTransformerFunction.function()
        .withAlgorithmFunction(c -> JWSAlgorithm.RS256);

    final JWK jwk = function.apply(credential);
    assertNotNull(jwk);
    assertEquals(JWSAlgorithm.RS256, jwk.getAlgorithm());
  }

  @Test
  void testRSAKeyIsSerializable() throws KeyStoreException {

    // Tries to serialize jwk, throws UncheckedIOException if jwk is not serializable
    final BiConsumer<JwkTransformerFunction, PkiCredential> jwkSerialize = (function, pki) -> {
      try {
        new ObjectOutputStream(new ByteArrayOutputStream()).writeObject(function.apply(pki));
      }
      catch (final IOException e) {
        throw new UncheckedIOException(e);
      }
    };

    final PkiCredential credential = new KeyStoreCredential(this.keyStore, ALIAS_RSA, PW);

    final JwkTransformerFunction customizedFunction = new JwkTransformerFunction()
        .serializable();

    final JwkTransformerFunction defaultFunction = new JwkTransformerFunction();

    Assertions.assertThrows(UncheckedIOException.class, () -> jwkSerialize.accept(defaultFunction, credential));
    Assertions.assertDoesNotThrow(() -> jwkSerialize.accept(customizedFunction, credential));
  }

  @Test
  void testEcKeyIsSerializable() throws KeyStoreException {

    //Tries to serialize jwk, throws UncheckedIOException if jwk is not serializable
    final BiConsumer<JwkTransformerFunction, PkiCredential> jwkSerialize = (function, pki) -> {
      try {
        new ObjectOutputStream(new ByteArrayOutputStream()).writeObject(function.apply(pki));
      }
      catch (final IOException e) {
        throw new UncheckedIOException(e);
      }
    };

    final PkiCredential credential = new KeyStoreCredential(this.keyStore, ALIAS_EC, PW);

    final JwkTransformerFunction customizedFunction = new JwkTransformerFunction()
        .serializable();

    final JwkTransformerFunction defaultFunction = new JwkTransformerFunction();

    Assertions.assertThrows(UncheckedIOException.class, () -> jwkSerialize.accept(defaultFunction, credential));
    Assertions.assertDoesNotThrow(() -> jwkSerialize.accept(customizedFunction, credential));
  }

}
