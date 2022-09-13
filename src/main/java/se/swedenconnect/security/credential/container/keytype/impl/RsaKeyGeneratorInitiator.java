package se.swedenconnect.security.credential.container.keytype.impl;


import se.swedenconnect.security.credential.container.keytype.KeyGeneratorInitiator;

import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class RsaKeyGeneratorInitiator extends KeyGeneratorInitiator {

  private int keySize;

  public RsaKeyGeneratorInitiator(String keyTypeName, int keySize) {
    super(keyTypeName);
    this.keySize = keySize;
  }

  /**
   * Initiate the HSM key generator with the key specification necessary to produce the desired key type.
   *
   * @param keyPairGenerator
   */
  @Override public void initiateKeyGenerator(KeyPairGenerator keyPairGenerator) throws GeneralSecurityException {
    keyPairGenerator.initialize(keySize);
  }

  /**
   * Get the algorithm name used to create the appropriate key generator
   *
   * @return key generator algorithm name
   */
  @Override public String getAlgorithmName() {
    return "RSA";
  }

}
