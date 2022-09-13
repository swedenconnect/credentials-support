package se.swedenconnect.security.credential.container.impl;

import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.container.credential.ErasableExternalChainCredential;
import se.swedenconnect.security.credential.container.exceptions.PkiCredentialContainerException;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.CertificateException;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class HSMMultiCredentialContainer extends AbstractMultiCredentialContainer {
  /**
   * Constructor for the default PKCS11KeyGenerator
   *
   * @param p11Provider the provider that provides access to the HSM key slot used to generate and store keys
   * @param hsmPin the pin for the associated HSM slot
   * @throws KeyStoreException error initiating the HSM slot key store
   * @throws CertificateException error parsing certificates in the HSM slot
   * @throws IOException general error processing data
   * @throws NoSuchAlgorithmException algorithm not supported
   */
  public HSMMultiCredentialContainer(Provider p11Provider, String hsmPin)
    throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
    super(p11Provider, hsmPin);
  }


  /**
   * Default overridable function to create the HSM slot key store used to store generated HSM keys.
   *
   * @param provider the provider for the HSM slot
   * @param password the pin code for the HSM slot
   * @return key store
   * @throws KeyStoreException error creating the key store
   * @throws CertificateException error loading existing certificates in key store
   * @throws IOException error in input data
   * @throws NoSuchAlgorithmException unsupported algorithm
   */
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
