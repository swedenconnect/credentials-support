package se.swedenconnect.security.credential.container.impl;

import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.container.AbstractPkiCredentialContainer;
import se.swedenconnect.security.credential.container.credential.ErasableExternalChainCredential;
import se.swedenconnect.security.credential.container.exceptions.PkiCredentialContainerException;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.CertificateException;

/**
 * Implements a {@link se.swedenconnect.security.credential.container.PkiCredentialContainer} based on HSM
 * or in-memory key storage (i.e. not using a HSM device for key storage).
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class HSMPkiCredentialContainer extends AbstractPkiCredentialContainer {

  /**
   * Constructor for the default PKCS11 credential container where keys are stored in a HSM slot
   *
   * @param p11Provider the provider that provides access to the HSM key slot used to generate and store keys
   * @param hsmPin the pin for the associated HSM slot
   * @throws KeyStoreException error initiating the HSM slot key store
   */
  public HSMPkiCredentialContainer(Provider p11Provider, String hsmPin)
    throws KeyStoreException {
    super(p11Provider, hsmPin);
  }


  /** {@inheritDoc} */
  @Override
  protected KeyStore getKeyStore(final Provider provider, final String password)
    throws KeyStoreException {
    KeyStore p11KeyStore = KeyStore.getInstance("PKCS11", provider);
    try {
      p11KeyStore.load(null, password.toCharArray());
    }
    catch (IOException | NoSuchAlgorithmException | CertificateException e) {
      throw new KeyStoreException(e);
    }
    return p11KeyStore;
  }

  /** {@inheritDoc} */
  @Override
  public ErasableExternalChainCredential getCredential(String alias) throws PkiCredentialContainerException {
    PkiCredential hsmCredential = new KeyStoreCredential(
      null, "PKCS11", provider.getName(),
      this.password, alias, null
    );
    try {
      hsmCredential.init();
    }
    catch (Exception e) {
      throw new PkiCredentialContainerException("Failure to create user key HSM credential", e);
    }
    return new ErasableExternalChainCredential(hsmCredential, this.keyStore, alias);
  }

}
