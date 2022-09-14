package se.swedenconnect.security.credential.container.keytype.impl;

import se.swedenconnect.security.credential.container.keytype.KeyPairGeneratorFactory;

import javax.annotation.Nonnull;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Factory for elliptic curve key pair generators
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class RsaKeyPairGeneratorFactory extends KeyPairGeneratorFactory {

  /** Key size for the generated RSA key */
  private int keySize;

  /**
   * Constructor for the RSA key pair generator factory
   *
   * @param keyTypeName the name of the key type associated with this key pair generator factory
   * @param keySize key size of generated RSA keys
   */
  public RsaKeyPairGeneratorFactory(final @Nonnull String keyTypeName,final int keySize) {
    super(keyTypeName);
    this.keySize = keySize;
  }

  /** {@inheritDoc} */
  @Override public KeyPairGenerator getKeyPairGenerator(final @Nonnull Provider provider) throws NoSuchAlgorithmException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", provider);
    keyPairGenerator.initialize(keySize);
    return keyPairGenerator;
  }
}
