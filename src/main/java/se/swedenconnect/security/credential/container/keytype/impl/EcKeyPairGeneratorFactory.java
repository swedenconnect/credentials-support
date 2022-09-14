package se.swedenconnect.security.credential.container.keytype.impl;

import se.swedenconnect.security.credential.container.keytype.KeyPairGeneratorFactory;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Factory for elliptic curve key pair generators
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class EcKeyPairGeneratorFactory extends KeyPairGeneratorFactory {

  /** Algorithm parameter specification for the elliptic curve to generate */
  private final AlgorithmParameterSpec algorithmParameterSpec;

  /**
   * Constructor for the Elliptic curve key pair generator factory
   *
   * @param keyTypeName the name of the key type associated with this key pair generator factory
   * @param algorithmParameterSpec algorithm specification for the specified key type
   */
  public EcKeyPairGeneratorFactory(String keyTypeName, AlgorithmParameterSpec algorithmParameterSpec) {
    super(keyTypeName);
    this.algorithmParameterSpec = algorithmParameterSpec;
  }

  /** {@inheritDoc} */
  @Override
  public KeyPairGenerator getKeyPairGenerator(Provider provider) throws NoSuchAlgorithmException,
    KeyException {

    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", provider);
    try {
      keyPairGenerator.initialize(algorithmParameterSpec);
    }
    catch (InvalidAlgorithmParameterException e) {
      throw new KeyException(e);
    }
    return keyPairGenerator;
  }
}
