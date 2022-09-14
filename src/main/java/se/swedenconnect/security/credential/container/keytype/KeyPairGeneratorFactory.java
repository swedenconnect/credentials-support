package se.swedenconnect.security.credential.container.keytype;

import lombok.Getter;

import javax.annotation.Nonnull;
import java.security.KeyException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

/**
 * Factory for creating a {@link KeyPairGenerator} suitable for a specific key type name
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public abstract class KeyPairGeneratorFactory {

  /** The name of the key type served by the instance of the key pair generator factory */
  @Getter private final String keyTypeName;

  /**
   * Abstract constructor setting the associated key type
   *
   * @param keyTypeName name of the key type served by this factory
   */
  public KeyPairGeneratorFactory(final @Nonnull String keyTypeName) {
    this.keyTypeName = keyTypeName;
  }

  /**
   * Create a key pair generator
   *
   * @param provider the crypto provider used to create the key pair generator
   * @return a {@link KeyPairGenerator}
   * @throws NoSuchAlgorithmException the key type served by this factory instance is not supported by the specified provider
   * @throws KeyException error initiating the key pair generator
   */
  public abstract KeyPairGenerator getKeyPairGenerator(final Provider provider) throws NoSuchAlgorithmException, KeyException;

  /**
   * Predicate for whether this factory instance supports a particular key type
   *
   * @param keyType the requested key type
   * @return true if this factory instance supports the specified key type
   */
  public boolean supports(final String keyType) {
    return this.keyTypeName.equalsIgnoreCase(keyType);
  }
}
