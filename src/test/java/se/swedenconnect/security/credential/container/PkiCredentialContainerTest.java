package se.swedenconnect.security.credential.container;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import se.swedenconnect.security.credential.AbstractReloadablePkiCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.container.keytype.*;

import java.io.IOException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the PkiCredentialContainer
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class PkiCredentialContainerTest {

  @BeforeAll
  static void init() throws Exception {
    if (Security.getProvider("BC") == null) {
      Security.insertProviderAt(new BouncyCastleProvider(), 2);
    }
  }

  @Test
  void createCredentialContainer() throws Exception {
    log.info("Testing credential container constructor");
    AbstractPkiCredentialContainer credentialContainer = new SoftPkiCredentialContainer(Security.getProvider("BC"),
      "Test1234");
    log.info("Credential container created with specified provider");
    String alias = credentialContainer.generateCredential(KeyGenType.EC_P256);
    assertNotNull(credentialContainer.getCredential(alias));

    credentialContainer = new SoftPkiCredentialContainer("Test456");
    log.info("Credential container created with default provider");
    assertEquals("BC", credentialContainer.getProvider().getName());
    alias = credentialContainer.generateCredential(KeyGenType.EC_P521);
    assertNotNull(credentialContainer.getCredential(alias));
  }

  @Test
  void testCleanup() throws Exception {
    log.info("Testing credential container cleanup");
    AbstractPkiCredentialContainer credentialContainer = new SoftPkiCredentialContainer("Test1234");
    credentialContainer.setKeyValidity(Duration.ofMillis(200));
    credentialContainer.generateCredential(KeyGenType.EC_P256);
    assertEquals(1, credentialContainer.listCredentials().size());
    Thread.sleep(200);
    credentialContainer.cleanup();
    assertEquals(0, credentialContainer.listCredentials().size());
    log.info("Credential cleanup test passed");
  }

  @Test
  void testAlgorithmTypes() throws Exception {
    log.info("Testing that correct key algorithm is being used");
    List<String> fullKeyTypeList = getFullKeyTypeList();
    AbstractPkiCredentialContainer credentialContainer = new SoftPkiCredentialContainer("Test1234");
    credentialContainer.setSupportedKeyTypes(fullKeyTypeList);

    // Fist attempt to issue credentials for the default key generator factories (for HSM use)
    for (String keyType : fullKeyTypeList) {
      credentialContainer.generateCredential(keyType);
    }
    assertEquals(fullKeyTypeList.size(), credentialContainer.listCredentials().size());
    // Register the named brainpool curves instead of explicit spec curves
    registerBrainPoolNamedCurveSpecs();

    // Test that we create keys of the right type
    for (String keyType : fullKeyTypeList) {
      log.info("Generating key of type: {}", keyType);
      verifyKeyType(keyType, credentialContainer);
      log.info("Key type confirmed");
    }

    KeyPairGeneratorFactory ecP256KeyGenFactory = KeyPairGeneratorFactoryRegistry.getFactory(KeyGenType.EC_P256);
    assertTrue(ecP256KeyGenFactory.supports(KeyGenType.EC_P256));
    assertFalse(ecP256KeyGenFactory.supports(KeyGenType.EC_BRAINPOOL_192));

    // Check that we can only ask for registered key types in the registry
    assertThrows(IllegalArgumentException.class, () -> KeyPairGeneratorFactoryRegistry.getFactory("BAD_Alog"));

  }

  @Test
  void testCredentials() throws Exception {
    AbstractPkiCredentialContainer credentialContainer = new SoftPkiCredentialContainer("Test1234");
    credentialContainer.setKeyValidity(Duration.ofDays(30));
    log.info("Testing expiry time -  duration set to 30 days");
    String alias = credentialContainer.generateCredential(KeyGenType.EC_P256);
    AbstractReloadablePkiCredential credential = (AbstractReloadablePkiCredential) credentialContainer.getCredential(alias);
    Instant expiryTime = credentialContainer.getExpiryTime(alias);
    log.info("Expiry time: {}", expiryTime);
    Instant before = Instant.ofEpochMilli(System.currentTimeMillis() + Duration.ofDays(29).toMillis());
    Instant after = Instant.ofEpochMilli(System.currentTimeMillis() + Duration.ofDays(31).toMillis());
    assertTrue(expiryTime.isAfter(before));
    assertTrue(expiryTime.isBefore(after));
    log.info("Expiry time is between expected range");

    X509Certificate certificate = credential.getCertificate();
    assertEquals(alias, certificate.getSerialNumber().toString(16));

    Method issueCert = AbstractPkiCredentialContainer.class.getDeclaredMethod("generateKeyCertificate", KeyPair.class, BigInteger.class);
    issueCert.setAccessible(true);
    KeyPair credentialKeyPair = new KeyPair(credential.getPublicKey(), credential.getPrivateKey());
    BigInteger newCertSerial = new BigInteger("1000ff", 16);
    X509Certificate newCert = (X509Certificate) issueCert.invoke(credentialContainer, credentialKeyPair, newCertSerial);
    credential.setCertificate(newCert);
    assertEquals(newCertSerial, credential.getCertificate().getSerialNumber());
    assertEquals(newCertSerial, credential.getCertificateChain().get(0).getSerialNumber());
    log.info("Successfully setting new certificate in credential");
    BigInteger newCertSerial2 = new BigInteger("9fee0012", 16);
    X509Certificate newCert2 = (X509Certificate) issueCert.invoke(credentialContainer, credentialKeyPair, newCertSerial2);
    credential.setCertificateChain(List.of(newCert2));
    assertEquals(newCertSerial2, credential.getCertificate().getSerialNumber());
    assertEquals(newCertSerial2, credential.getCertificateChain().get(0).getSerialNumber());
    log.info("Successfully setting new certificate chain in credential");
    // make sure relaod does not casue any exception
    credential.reload();

    // Ensure that it is not possible to set public key
    IllegalArgumentException setPubKeyEx = assertThrows(IllegalArgumentException.class,
      () -> credential.setPublicKey(credential.getPublicKey()));
    log.info("Setting public key cause expected exception: {}", setPubKeyEx.getMessage());

    // Ensure that it is not possible to set private key
    IllegalArgumentException setprivKeyEx = assertThrows(IllegalArgumentException.class,
      () -> credential.setPrivateKey(credential.getPrivateKey()));
    log.info("Setting public key cause expected exception: {}", setprivKeyEx.getMessage());

    String name = credential.getName();
    assertEquals(alias, name);
  }


  @Test
  void generateKeyPair() throws Exception {

    AbstractPkiCredentialContainer credentialContainer = new SoftPkiCredentialContainer(Security.getProvider("BC"),
      "Test1234");
    List<String> keyTypeIdList = getFullKeyTypeList();
    credentialContainer.setSupportedKeyTypes(keyTypeIdList);

    List<PkiCredential> credentialList = issueKeyTypes(keyTypeIdList, credentialContainer);
    assertEquals(keyTypeIdList.size(), credentialList.size());

    List<String> availableCredentials = credentialContainer.listCredentials();
    log.info("Available credentials: {}", availableCredentials);

    assertEquals(keyTypeIdList.size(), availableCredentials.size());

    for (PkiCredential credential : credentialList) {
      credential.destroy();
    }

    assertEquals(0, credentialContainer.listCredentials().size());

    // Issue credentials again:
    credentialList = issueKeyTypes(keyTypeIdList, credentialContainer);
    assertEquals(keyTypeIdList.size(), credentialList.size());

    // Delete them using the pkcs11 key generator
    availableCredentials = credentialContainer.listCredentials();
    for (String alias : availableCredentials) {
      credentialContainer.deleteCredential(alias);
    }

    // make sure they are deleted
    assertEquals(0, credentialContainer.listCredentials().size());

  }

  List<PkiCredential> issueKeyTypes(List<String> keyTypeIdList, PkiCredentialContainer pkiCredentialContainer)
    throws GeneralSecurityException, PkiCredentialContainerException {
    List<PkiCredential> credentialList = new ArrayList<>();
    for (String keyTypeId : keyTypeIdList) {
      log.info("Generating key of type: {}", keyTypeId);
      String alias = pkiCredentialContainer.generateCredential(keyTypeId);
      PkiCredential credential = pkiCredentialContainer.getCredential(alias);
      assertNotNull(credential);
      credentialList.add(credential);
    }
    return credentialList;
  }

  @Test
  void nullProviderTest() throws Exception {
    errorTest("Null provider test", NullPointerException.class, () -> {
      new SoftPkiCredentialContainer(null, "Test1234");
    });
  }

  @Test
  void nullHsmPinTest() throws Exception {
    errorTest("Null hsm pin test", NullPointerException.class, () -> {
      new SoftPkiCredentialContainer(Security.getProvider("BC"), null);
    });
  }

  @Test
  void unsupportedAlgoTest() throws Exception {
    AbstractPkiCredentialContainer pkcs11KeyGenerator = new SoftPkiCredentialContainer("Test1234");
    errorTest("Unsupported algorithm", NoSuchAlgorithmException.class, () -> {
      pkcs11KeyGenerator.generateCredential("DUMMY_ALOG");
    });
  }

  @Test
  void excludedAlgoTest() throws Exception {
    AbstractPkiCredentialContainer pkcs11KeyGenerator = new SoftPkiCredentialContainer("Test1234");
    errorTest("Excluded algorithm", NoSuchAlgorithmException.class, () -> {
      pkcs11KeyGenerator.generateCredential(KeyGenType.EC_BRAINPOOL_192);
    });
  }

  @Test
  void unknownKeyTest() throws Exception {
    AbstractPkiCredentialContainer pkcs11KeyGenerator = new SoftPkiCredentialContainer("Test1234");
    errorTest("Get unknown key", PkiCredentialContainerException.class, () -> {
      pkcs11KeyGenerator.getCredential("unknown");
    });
  }

  @Test
  void deleteUnknownKeyTest() throws Exception {
    AbstractPkiCredentialContainer pkcs11KeyGenerator = new SoftPkiCredentialContainer("Test1234");
    errorTest("Delete unknown key", PkiCredentialContainerException.class, () -> {
      pkcs11KeyGenerator.getCredential("unknown");
    });
  }


  void errorTest(String message, Class<? extends Exception> expectedType, Executable executable) {
    Exception exception = assertThrows(expectedType, executable);
    log.info("{}: {}", message, exception.toString());
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
      KeyGenType.EC_BRAINPOOL_512
    );
  }

  private List<String> getTypicalKeyTypeList() {
    return List.of(
      KeyGenType.RSA_3072,
      KeyGenType.RSA_4096,
      KeyGenType.EC_P256,
      KeyGenType.EC_P384,
      KeyGenType.EC_P521
    );
  }

  private ASN1ObjectIdentifier getEcKeyNamedCureOid(ECPublicKey publicKey) throws IOException {
    byte[] encoded = publicKey.getEncoded();
    ASN1Sequence pkSequence = ASN1Sequence.getInstance(new ASN1InputStream(encoded).readObject());
    ASN1Sequence oidSequence = ASN1Sequence.getInstance(pkSequence.getObjectAt(0));
    return ASN1ObjectIdentifier.getInstance(oidSequence.getObjectAt(1));
  }

  private void verifyKeyType(String keyType, AbstractPkiCredentialContainer credentialContainer) throws Exception {
    String alias = credentialContainer.generateCredential(keyType);
    PkiCredential credential = credentialContainer.getCredential(alias);
    PublicKey publicKey = credential.getPublicKey();

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
      assertEquals(SECObjectIdentifiers.secp192r1, getEcKeyNamedCureOid((ECPublicKey) publicKey));
      break;
    case KeyGenType.EC_P224:
      assertEquals(SECObjectIdentifiers.secp224r1, getEcKeyNamedCureOid((ECPublicKey) publicKey));
      break;
    case KeyGenType.EC_P256:
      assertEquals(SECObjectIdentifiers.secp256r1, getEcKeyNamedCureOid((ECPublicKey) publicKey));
      break;
    case KeyGenType.EC_P384:
      assertEquals(SECObjectIdentifiers.secp384r1, getEcKeyNamedCureOid((ECPublicKey) publicKey));
      break;
    case KeyGenType.EC_P521:
      assertEquals(SECObjectIdentifiers.secp521r1, getEcKeyNamedCureOid((ECPublicKey) publicKey));
      break;
    case KeyGenType.EC_BRAINPOOL_192:
      assertEquals(new ASN1ObjectIdentifier("1.3.36.3.3.2.8.1.1.3"), getEcKeyNamedCureOid((ECPublicKey) publicKey));
      break;
    case KeyGenType.EC_BRAINPOOL_224:
      assertEquals(new ASN1ObjectIdentifier("1.3.36.3.3.2.8.1.1.5"), getEcKeyNamedCureOid((ECPublicKey) publicKey));
      break;
    case KeyGenType.EC_BRAINPOOL_256:
      assertEquals(new ASN1ObjectIdentifier("1.3.36.3.3.2.8.1.1.7"), getEcKeyNamedCureOid((ECPublicKey) publicKey));
      break;
    case KeyGenType.EC_BRAINPOOL_320:
      assertEquals(new ASN1ObjectIdentifier("1.3.36.3.3.2.8.1.1.9"), getEcKeyNamedCureOid((ECPublicKey) publicKey));
      break;
    case KeyGenType.EC_BRAINPOOL_384:
      assertEquals(new ASN1ObjectIdentifier("1.3.36.3.3.2.8.1.1.11"), getEcKeyNamedCureOid((ECPublicKey) publicKey));
      break;
    case KeyGenType.EC_BRAINPOOL_512:
      assertEquals(new ASN1ObjectIdentifier("1.3.36.3.3.2.8.1.1.13"), getEcKeyNamedCureOid((ECPublicKey) publicKey));
      break;
    default:
      throw new NoSuchAlgorithmException("Requested algorithm is not supported: " + keyType);
    }
  }

  private void registerBrainPoolNamedCurveSpecs() {
    // Registering Brainpool curves based on named parameter specs rather than explicit specs in order to test keys generated in software
    KeyPairGeneratorFactoryRegistry.registerFactory(KeyGenType.EC_BRAINPOOL_192, new EcKeyPairGeneratorFactory(KeyGenType.EC_BRAINPOOL_192,
      ECParameterSpecs.APS_BRAINPOOL_P192R1));
    KeyPairGeneratorFactoryRegistry.registerFactory(KeyGenType.EC_BRAINPOOL_224, new EcKeyPairGeneratorFactory(KeyGenType.EC_BRAINPOOL_224,
      ECParameterSpecs.APS_BRAINPOOL_P224R1));
    KeyPairGeneratorFactoryRegistry.registerFactory(KeyGenType.EC_BRAINPOOL_256, new EcKeyPairGeneratorFactory(KeyGenType.EC_BRAINPOOL_256,
      ECParameterSpecs.APS_BRAINPOOL_P256R1));
    KeyPairGeneratorFactoryRegistry.registerFactory(KeyGenType.EC_BRAINPOOL_320, new EcKeyPairGeneratorFactory(KeyGenType.EC_BRAINPOOL_320,
      ECParameterSpecs.APS_BRAINPOOL_P320R1));
    KeyPairGeneratorFactoryRegistry.registerFactory(KeyGenType.EC_BRAINPOOL_384, new EcKeyPairGeneratorFactory(KeyGenType.EC_BRAINPOOL_384,
      ECParameterSpecs.APS_BRAINPOOL_P384R1));
    KeyPairGeneratorFactoryRegistry.registerFactory(KeyGenType.EC_BRAINPOOL_512, new EcKeyPairGeneratorFactory(KeyGenType.EC_BRAINPOOL_512,
      ECParameterSpecs.APS_BRAINPOOL_P512R1));
  }


}