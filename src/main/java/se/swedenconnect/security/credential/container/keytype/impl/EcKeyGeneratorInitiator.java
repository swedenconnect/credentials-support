package se.swedenconnect.security.credential.container.keytype.impl;


import se.swedenconnect.security.credential.container.keytype.KeyGeneratorInitiator;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class EcKeyGeneratorInitiator extends KeyGeneratorInitiator {

  private final AlgorithmParameterSpec algorithmParameterSpec;

  public EcKeyGeneratorInitiator(String keyTypeName, AlgorithmParameterSpec algorithmParameterSpec) {
    super(keyTypeName);
    this.algorithmParameterSpec = algorithmParameterSpec;
  }

  /**
   * Initiate the HSM key generator with the key specification necessary to produce the desired key type.
   *
   * @param keyPairGenerator
   */
  @Override public void initiateKeyGenerator(KeyPairGenerator keyPairGenerator)
    throws InvalidAlgorithmParameterException {
    keyPairGenerator.initialize(algorithmParameterSpec);
  }

  /**
   * Get the algorithm name used to create the appropriate key generator
   *
   * @return key generator algorithm name
   */
  @Override public String getAlgorithmName() {
    return "EC";
  }
}
