package se.swedenconnect.security.credential.container.keytype;

import lombok.Getter;

import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public abstract class KeyGeneratorInitiator {

  @Getter private final String keyTypeName;

  public KeyGeneratorInitiator(String keyTypeName) {
    this.keyTypeName = keyTypeName;
  }

  /**
   * Initiate the HSM key generator with the key specification necessary to produce the desired key type.
   * @param keyPairGenerator
   */
  public abstract void initiateKeyGenerator(KeyPairGenerator keyPairGenerator)
    throws GeneralSecurityException;

  /**
   * Get the algorithm name used to create the appropriate key generator
   *
   * @return key generator algorithm name
   */
  public abstract String getAlgorithmName();

  /**
   * Test if this HSM key generator initiator supports the key type represented by a particular
   * key type name
   *
   * @param hsmKeyTypeName HSM key type name
   * @return true if this key generator initiator supports the specified hsmKeyTypeName
   */
  public boolean supports(String hsmKeyTypeName) {
    return (this.keyTypeName.equalsIgnoreCase(hsmKeyTypeName));
  }

}
