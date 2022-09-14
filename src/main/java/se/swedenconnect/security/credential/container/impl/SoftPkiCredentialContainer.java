package se.swedenconnect.security.credential.container.impl;

import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.container.AbstractPkiCredentialContainer;
import se.swedenconnect.security.credential.container.credential.ErasableExternalChainCredential;
import se.swedenconnect.security.credential.container.exceptions.PkiCredentialContainerException;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.util.Objects;

/**
 * Implements a {@link se.swedenconnect.security.credential.container.PkiCredentialContainer} based on software
 * or in-memory key storage (i.e. not using a HSM device for key storage).
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class SoftPkiCredentialContainer extends AbstractPkiCredentialContainer {
  /**
   * Constructor for the multi credential key store
   *
   * @param provider the provider that provides access to the HSM key slot used to generate and store keys
   * @param password the pin for the associated HSM slot
   * @throws KeyStoreException error initiating the HSM slot key store
   */
  public SoftPkiCredentialContainer(Provider provider, String password)
    throws KeyStoreException {
    super(provider, password);
  }

  /** {@inheritDoc} */
  @Override public ErasableExternalChainCredential getCredential(final @Nonnull String alias) throws PkiCredentialContainerException {
    Objects.requireNonNull(alias, "Key alias must not be null");

    KeyStoreCredential credential = new KeyStoreCredential(this.keyStore, alias, this.password);
    try {
      credential.init();
    }
    catch (Exception e) {
      throw new PkiCredentialContainerException("Error initiating key store credential", e);
    }
    return new ErasableExternalChainCredential(credential, this.keyStore, alias);
  }

  /** {@inheritDoc} */
  @Override protected KeyStore getKeyStore(final @Nonnull Provider provider, final @Nonnull String password)
    throws KeyStoreException {
    KeyStore testKeyStore = KeyStore.getInstance(KeyStore.getDefaultType(), provider);
    try {
      testKeyStore.load(null, password.toCharArray());
    }
    catch (IOException | NoSuchAlgorithmException | CertificateException e) {
      throw new KeyStoreException(e);
    }
    return testKeyStore;
  }
}
