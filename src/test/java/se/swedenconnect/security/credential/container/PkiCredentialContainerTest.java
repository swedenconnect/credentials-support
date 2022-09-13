package se.swedenconnect.security.credential.container;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.container.exceptions.PkiCredentialContainerException;
import se.swedenconnect.security.credential.container.impl.AbstractMultiCredentialContainer;
import se.swedenconnect.security.credential.container.impl.SoftMultiCredentialContainer;
import se.swedenconnect.security.credential.container.keytype.KeyGenType;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class PkiCredentialContainerTest {

  @BeforeAll
  static void init() throws Exception {
    Security.insertProviderAt(new BouncyCastleProvider(), 2);
  }

  @Test
  void generateKeyPair() throws Exception {

    AbstractMultiCredentialContainer pkcs11KeyGenerator = new SoftMultiCredentialContainer(Security.getProvider("BC"), "Test1234");
    pkcs11KeyGenerator.setSupportedKeyGenInitiators(List.of(
      KeyGenType.RSA_2048_Initiator,
      KeyGenType.RSA_3072_Initiator,
      KeyGenType.RSA_4096_Initiator,
      KeyGenType.EC_P192_Initiator,
      KeyGenType.EC_P224_Initiator,
      KeyGenType.EC_P256_Initiator,
      KeyGenType.EC_P384_Initiator,
      KeyGenType.EC_P521_Initiator,
      KeyGenType.EC_BRAINPOOL_192_Initiator,
      KeyGenType.EC_BRAINPOOL_224_Initiator,
      KeyGenType.EC_BRAINPOOL_256_Initiator,
      KeyGenType.EC_BRAINPOOL_320_Initiator,
      KeyGenType.EC_BRAINPOOL_384_Initiator,
      KeyGenType.EC_BRAINPOOL_512_Initiator
    ));

    List<String> keyTypeIdList = List.of(
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

    List<PkiCredential> credentialList = issueKeyTypes(keyTypeIdList, pkcs11KeyGenerator);
    assertEquals(keyTypeIdList.size(), credentialList.size());

    List<String> availableCredentials = pkcs11KeyGenerator.getAvailableCredentials();
    log.info("Available credentials: {}", availableCredentials);

    assertEquals(keyTypeIdList.size(), availableCredentials.size());

    for (PkiCredential credential : credentialList) {
      credential.destroy();
    }

    assertEquals(0, pkcs11KeyGenerator.getAvailableCredentials().size());

    // Issue credentials again:
    credentialList = issueKeyTypes(keyTypeIdList, pkcs11KeyGenerator);
    assertEquals(keyTypeIdList.size(), credentialList.size());

    // Delete them using the pkcs11 key generator
    availableCredentials = pkcs11KeyGenerator.getAvailableCredentials();
    for (String alias : availableCredentials) {
      pkcs11KeyGenerator.deleteCredential(alias);
    }

    // make sure they are deleted
    assertEquals(0, pkcs11KeyGenerator.getAvailableCredentials().size());

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
  void errorTests() throws Exception {

    errorTest("Null provider test", NullPointerException.class, () -> {
      new SoftMultiCredentialContainer(null, "Test1234");
    });

    errorTest("Null hsm pin test", NullPointerException.class, () -> {
      new SoftMultiCredentialContainer(Security.getProvider("BC"), null);
    });

    AbstractMultiCredentialContainer pkcs11KeyGenerator = new SoftMultiCredentialContainer(Security.getProvider("BC"), "Test1234");
    errorTest("Unsupported algorithm", NoSuchAlgorithmException.class, () -> {
      pkcs11KeyGenerator.generateCredential("DUMMY_ALOG");
    });

    errorTest("Excluded algorithm", NoSuchAlgorithmException.class, () -> {
      pkcs11KeyGenerator.generateCredential(KeyGenType.EC_BRAINPOOL_192);
    });

    errorTest("Get unknown key", PkiCredentialContainerException.class, () -> {
      pkcs11KeyGenerator.getCredential("unknown");
    });

    errorTest("Delete unknown key", PkiCredentialContainerException.class, () -> {
      pkcs11KeyGenerator.getCredential("unknown");
    });

  }

  void errorTest(String message, Class<? extends Exception> expectedType, Executable executable) {
    Exception exception = assertThrows(expectedType, executable);
    log.info("{}: {}", message, exception.toString());
  }

}