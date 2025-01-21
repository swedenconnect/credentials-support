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
package se.swedenconnect.security.credential.container;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.container.keytype.ECParameterSpecs;
import se.swedenconnect.security.credential.container.keytype.EcKeyPairGeneratorFactory;
import se.swedenconnect.security.credential.container.keytype.KeyGenType;
import se.swedenconnect.security.credential.container.keytype.KeyPairGeneratorFactory;
import se.swedenconnect.security.credential.container.keytype.KeyPairGeneratorFactoryRegistry;

import java.io.IOException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for the PkiCredentialContainer.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class PkiCredentialContainerTest {

  @BeforeAll
  static void init() {
    if (Security.getProvider("BC") == null) {
      Security.insertProviderAt(new BouncyCastleProvider(), 2);
    }
  }

  @Test
  void createCredentialContainer() throws Exception {
    AbstractKeyStorePkiCredentialContainer credentialContainer =
        new SoftPkiCredentialContainer(Security.getProvider("BC"),
            "Test1234");

    String alias = credentialContainer.generateCredential(KeyGenType.EC_P256);
    assertNotNull(credentialContainer.getCredential(alias));

    credentialContainer = new SoftPkiCredentialContainer("BC", "Test456");
    assertEquals("BC", credentialContainer.getProvider().getName());
    alias = credentialContainer.generateCredential(KeyGenType.EC_P521);
    assertNotNull(credentialContainer.getCredential(alias));
  }

  @Test
  void testCleanup() throws Exception {
    final AbstractKeyStorePkiCredentialContainer credentialContainer = new SoftPkiCredentialContainer("BC", "Test1234");
    credentialContainer.setKeyValidity(Duration.ofMillis(200));
    final String expiredAlias = credentialContainer.generateCredential(KeyGenType.EC_P256);
    credentialContainer.generateCredential(KeyGenType.EC_P256);
    assertEquals(2, credentialContainer.listCredentials().size());
    Thread.sleep(200);
    // First test that it is not possible to get an expired credential
    assertThrows(PkiCredentialContainerException.class, () -> credentialContainer.getCredential(expiredAlias));
    // Check that the key is destroyed
    assertEquals(1, credentialContainer.listCredentials().size());
    // Now do a cleanup
    credentialContainer.cleanup();
    // Ensure that all keys are deleted
    assertEquals(0, credentialContainer.listCredentials().size());
  }

  @Test
  void testAlgorithmTypes() throws Exception {
    final List<String> fullKeyTypeList = this.getFullKeyTypeList();
    final AbstractKeyStorePkiCredentialContainer credentialContainer = new SoftPkiCredentialContainer("BC", "Test1234");
    credentialContainer.setSupportedKeyTypes(fullKeyTypeList);

    // Fist attempt to issue credentials for the default key generator factories (for HSM use)
    for (final String keyType : fullKeyTypeList) {
      credentialContainer.generateCredential(keyType);
    }
    assertEquals(fullKeyTypeList.size(), credentialContainer.listCredentials().size());
    // Register the named brainpool curves instead of explicit spec curves
    this.registerBrainPoolNamedCurveSpecs();

    // Test that we create keys of the right type
    for (final String keyType : fullKeyTypeList) {
      this.verifyKeyType(keyType, credentialContainer);
    }

    final KeyPairGeneratorFactory ecP256KeyGenFactory = KeyPairGeneratorFactoryRegistry.getFactory(KeyGenType.EC_P256);
    assertTrue(ecP256KeyGenFactory.supports(KeyGenType.EC_P256));
    assertFalse(ecP256KeyGenFactory.supports(KeyGenType.EC_BRAINPOOL_192));

    // Check that we can only ask for registered key types in the registry
    assertThrows(IllegalArgumentException.class, () -> KeyPairGeneratorFactoryRegistry.getFactory("BAD_Alog"));
  }

  @Test
  void testCredentials() throws Exception {
    final AbstractKeyStorePkiCredentialContainer credentialContainer = new SoftPkiCredentialContainer("BC", "Test1234");
    credentialContainer.setKeyValidity(Duration.ofDays(30));

    final String alias = credentialContainer.generateCredential(KeyGenType.EC_P256);
    final ManagedPkiCredential credential = credentialContainer.getCredential(alias);
    final Instant expiryTime = credentialContainer.getExpiryTime(alias);

    final Instant before = Instant.ofEpochMilli(System.currentTimeMillis() + Duration.ofDays(29).toMillis());
    final Instant after = Instant.ofEpochMilli(System.currentTimeMillis() + Duration.ofDays(31).toMillis());
    assertTrue(expiryTime.isAfter(before));
    assertTrue(expiryTime.isBefore(after));

    final X509Certificate certificate = credential.getCertificate();
    assertEquals(alias, certificate.getSerialNumber().toString(16));

    final Method issueCert =
        AbstractKeyStorePkiCredentialContainer.class.getDeclaredMethod("generateKeyCertificate", KeyPair.class,
            BigInteger.class);
    issueCert.setAccessible(true);
    final KeyPair credentialKeyPair = new KeyPair(credential.getPublicKey(), credential.getPrivateKey());
    final BigInteger newCertSerial = new BigInteger("1000ff", 16);
    final X509Certificate newCert =
        (X509Certificate) issueCert.invoke(credentialContainer, credentialKeyPair, newCertSerial);
    credential.setCertificate(newCert);
    assertEquals(newCertSerial, credential.getCertificate().getSerialNumber());
    assertEquals(newCertSerial, credential.getCertificateChain().get(0).getSerialNumber());

    final BigInteger newCertSerial2 = new BigInteger("9fee0012", 16);
    final X509Certificate newCert2 =
        (X509Certificate) issueCert.invoke(credentialContainer, credentialKeyPair, newCertSerial2);
    credential.setCertificateChain(List.of(newCert2));
    assertEquals(newCertSerial2, credential.getCertificate().getSerialNumber());
    assertEquals(newCertSerial2, credential.getCertificateChain().get(0).getSerialNumber());

    // make sure relaod does not casue any exception
    credential.reload();

    final String name = credential.getName();
    assertEquals(alias, name);
  }

  @Test
  public void testGenerateKeyPair() throws Exception {

    final AbstractKeyStorePkiCredentialContainer credentialContainer =
        new SoftPkiCredentialContainer(Security.getProvider("BC"), "Test1234");
    final List<String> keyTypeIdList = this.getFullKeyTypeList();
    credentialContainer.setSupportedKeyTypes(keyTypeIdList);

    List<PkiCredential> credentialList = this.issueKeyTypes(keyTypeIdList, credentialContainer);
    assertEquals(keyTypeIdList.size(), credentialList.size());

    List<String> availableCredentials = credentialContainer.listCredentials();
    log.info("Available credentials: {}", availableCredentials);

    assertEquals(keyTypeIdList.size(), availableCredentials.size());

    for (final PkiCredential credential : credentialList) {
      credential.destroy();
    }

    assertEquals(0, credentialContainer.listCredentials().size());

    // Issue credentials again:
    credentialList = this.issueKeyTypes(keyTypeIdList, credentialContainer);
    assertEquals(keyTypeIdList.size(), credentialList.size());

    // Delete them using the pkcs11 key generator
    availableCredentials = credentialContainer.listCredentials();
    for (final String alias : availableCredentials) {
      credentialContainer.deleteCredential(alias);
    }

    // make sure they are deleted
    assertEquals(0, credentialContainer.listCredentials().size());
  }

  List<PkiCredential> issueKeyTypes(final List<String> keyTypeIdList,
      final PkiCredentialContainer pkiCredentialContainer)
      throws GeneralSecurityException, PkiCredentialContainerException {
    final List<PkiCredential> credentialList = new ArrayList<>();
    for (final String keyTypeId : keyTypeIdList) {
      log.info("Generating key of type: {}", keyTypeId);
      final String alias = pkiCredentialContainer.generateCredential(keyTypeId);
      final PkiCredential credential = pkiCredentialContainer.getCredential(alias);
      assertNotNull(credential);
      credentialList.add(credential);
    }
    return credentialList;
  }

  @Test
  void nullProviderTest() {
    Assertions.assertThrows(NullPointerException.class,
        () -> new SoftPkiCredentialContainer((Provider) null, "Test1234"));
  }

  @Test
  void nullHsmPinTest() {
    final Provider dummyProvider = Mockito.mock(Provider.class);
    Assertions.assertThrows(NullPointerException.class, () -> new HsmPkiCredentialContainer(dummyProvider, null));
  }

  @Test
  public void testNullPassword() throws Exception {
    final AbstractKeyStorePkiCredentialContainer credentialContainer = new SoftPkiCredentialContainer("BC");
    final String alias = credentialContainer.generateCredential(KeyGenType.EC_P256);
    final PkiCredential cred = credentialContainer.getCredential(alias);
    Assertions.assertNotNull(cred);
  }

  @Test
  void unsupportedAlgoTest() throws Exception {
    final AbstractKeyStorePkiCredentialContainer container = new SoftPkiCredentialContainer("BC", "Test1234");
    Assertions.assertThrows(NoSuchAlgorithmException.class, () -> container.generateCredential("DUMMY"));
  }

  @Test
  void excludedAlgoTest() throws Exception {
    final AbstractKeyStorePkiCredentialContainer container = new SoftPkiCredentialContainer("BC", "Test1234");
    final Exception exc = Assertions.assertThrows(NoSuchAlgorithmException.class,
        () -> container.generateCredential(KeyGenType.EC_BRAINPOOL_192));
    Assertions.assertTrue(exc.getMessage().contains("is not supported by this container"));
  }

  @Test
  void unknownKeyTest() throws Exception {
    final AbstractKeyStorePkiCredentialContainer container = new SoftPkiCredentialContainer("BC", "Test1234");
    Assertions.assertThrows(PkiCredentialContainerException.class, () -> container.getCredential("unknown"));
  }

  @Test
  void unknownKeyExpiryTest() throws Exception {
    final AbstractKeyStorePkiCredentialContainer container = new SoftPkiCredentialContainer("BC", "Test1234");
    Assertions.assertThrows(PkiCredentialContainerException.class, () -> container.getExpiryTime("unknown"));
  }

  @Test
  void deleteUnknownKeyTest() throws Exception {
    final AbstractKeyStorePkiCredentialContainer container = new SoftPkiCredentialContainer("BC", "Test1234");
    Assertions.assertThrows(PkiCredentialContainerException.class, () -> container.getCredential("unknown"));
  }

  private List<String> getFullKeyTypeList() {
    return List.of(
        KeyGenType.RSA_2048,
        KeyGenType.RSA_3072,
        KeyGenType.RSA_4096,
        KeyGenType.EC_P192,
        KeyGenType.EC_P224,
        KeyGenType.EC_P256,
        KeyGenType.EC_P384,
        KeyGenType.EC_P521,
        KeyGenType.EC_BRAINPOOL_192,
        KeyGenType.EC_BRAINPOOL_224,
        KeyGenType.EC_BRAINPOOL_256,
        KeyGenType.EC_BRAINPOOL_320,
        KeyGenType.EC_BRAINPOOL_384,
        KeyGenType.EC_BRAINPOOL_512);
  }

  @SuppressWarnings("unused")
  private List<String> getTypicalKeyTypeList() {
    return List.of(
        KeyGenType.RSA_3072,
        KeyGenType.RSA_4096,
        KeyGenType.EC_P256,
        KeyGenType.EC_P384,
        KeyGenType.EC_P521);
  }

  private ASN1ObjectIdentifier getEcKeyNamedCureOid(final ECPublicKey publicKey) throws IOException {
    final byte[] encoded = publicKey.getEncoded();
    try (final ASN1InputStream as = new ASN1InputStream(encoded)) {
      final ASN1Sequence pkSequence = ASN1Sequence.getInstance(as.readObject());
      final ASN1Sequence oidSequence = ASN1Sequence.getInstance(pkSequence.getObjectAt(0));
      return ASN1ObjectIdentifier.getInstance(oidSequence.getObjectAt(1));
    }
  }

  private void verifyKeyType(final String keyType, final AbstractKeyStorePkiCredentialContainer credentialContainer)
      throws Exception {
    final String alias = credentialContainer.generateCredential(keyType);
    final PkiCredential credential = credentialContainer.getCredential(alias);
    final PublicKey publicKey = credential.getPublicKey();

    switch (keyType) {
    case KeyGenType.RSA_2048:
      assertEquals(2048, ((RSAPublicKey) publicKey).getModulus().bitLength());
      break;
    case KeyGenType.RSA_3072:
      assertEquals(3072, ((RSAPublicKey) publicKey).getModulus().bitLength());
      break;
    case KeyGenType.RSA_4096:
      assertEquals(4096, ((RSAPublicKey) publicKey).getModulus().bitLength());
      break;
    case KeyGenType.EC_P192:
      assertEquals(SECObjectIdentifiers.secp192r1, this.getEcKeyNamedCureOid((ECPublicKey) publicKey));
      break;
    case KeyGenType.EC_P224:
      assertEquals(SECObjectIdentifiers.secp224r1, this.getEcKeyNamedCureOid((ECPublicKey) publicKey));
      break;
    case KeyGenType.EC_P256:
      assertEquals(SECObjectIdentifiers.secp256r1, this.getEcKeyNamedCureOid((ECPublicKey) publicKey));
      break;
    case KeyGenType.EC_P384:
      assertEquals(SECObjectIdentifiers.secp384r1, this.getEcKeyNamedCureOid((ECPublicKey) publicKey));
      break;
    case KeyGenType.EC_P521:
      assertEquals(SECObjectIdentifiers.secp521r1, this.getEcKeyNamedCureOid((ECPublicKey) publicKey));
      break;
    case KeyGenType.EC_BRAINPOOL_192:
      assertEquals(new ASN1ObjectIdentifier("1.3.36.3.3.2.8.1.1.3"),
          this.getEcKeyNamedCureOid((ECPublicKey) publicKey));
      break;
    case KeyGenType.EC_BRAINPOOL_224:
      assertEquals(new ASN1ObjectIdentifier("1.3.36.3.3.2.8.1.1.5"),
          this.getEcKeyNamedCureOid((ECPublicKey) publicKey));
      break;
    case KeyGenType.EC_BRAINPOOL_256:
      assertEquals(new ASN1ObjectIdentifier("1.3.36.3.3.2.8.1.1.7"),
          this.getEcKeyNamedCureOid((ECPublicKey) publicKey));
      break;
    case KeyGenType.EC_BRAINPOOL_320:
      assertEquals(new ASN1ObjectIdentifier("1.3.36.3.3.2.8.1.1.9"),
          this.getEcKeyNamedCureOid((ECPublicKey) publicKey));
      break;
    case KeyGenType.EC_BRAINPOOL_384:
      assertEquals(new ASN1ObjectIdentifier("1.3.36.3.3.2.8.1.1.11"),
          this.getEcKeyNamedCureOid((ECPublicKey) publicKey));
      break;
    case KeyGenType.EC_BRAINPOOL_512:
      assertEquals(new ASN1ObjectIdentifier("1.3.36.3.3.2.8.1.1.13"),
          this.getEcKeyNamedCureOid((ECPublicKey) publicKey));
      break;
    default:
      throw new NoSuchAlgorithmException("Requested algorithm is not supported: " + keyType);
    }
  }

  private void registerBrainPoolNamedCurveSpecs() {
    // Registering Brainpool curves based on named parameter specs rather than explicit specs in order to test keys
    // generated in software
    KeyPairGeneratorFactoryRegistry.registerFactory(KeyGenType.EC_BRAINPOOL_192,
        new EcKeyPairGeneratorFactory(KeyGenType.EC_BRAINPOOL_192,
            ECParameterSpecs.APS_BRAINPOOL_P192R1));
    KeyPairGeneratorFactoryRegistry.registerFactory(KeyGenType.EC_BRAINPOOL_224,
        new EcKeyPairGeneratorFactory(KeyGenType.EC_BRAINPOOL_224,
            ECParameterSpecs.APS_BRAINPOOL_P224R1));
    KeyPairGeneratorFactoryRegistry.registerFactory(KeyGenType.EC_BRAINPOOL_256,
        new EcKeyPairGeneratorFactory(KeyGenType.EC_BRAINPOOL_256,
            ECParameterSpecs.APS_BRAINPOOL_P256R1));
    KeyPairGeneratorFactoryRegistry.registerFactory(KeyGenType.EC_BRAINPOOL_320,
        new EcKeyPairGeneratorFactory(KeyGenType.EC_BRAINPOOL_320,
            ECParameterSpecs.APS_BRAINPOOL_P320R1));
    KeyPairGeneratorFactoryRegistry.registerFactory(KeyGenType.EC_BRAINPOOL_384,
        new EcKeyPairGeneratorFactory(KeyGenType.EC_BRAINPOOL_384,
            ECParameterSpecs.APS_BRAINPOOL_P384R1));
    KeyPairGeneratorFactoryRegistry.registerFactory(KeyGenType.EC_BRAINPOOL_512,
        new EcKeyPairGeneratorFactory(KeyGenType.EC_BRAINPOOL_512,
            ECParameterSpecs.APS_BRAINPOOL_P512R1));
  }

}
