package se.swedenconnect.security.credential.container.impl;

import se.swedenconnect.security.credential.KeyStoreCredential;
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
public class SoftMultiCredentialContainer extends AbstractMultiCredentialContainer {
  /**
   * Constructor for the multi credential key store
   *
   * @param provider the provider that provides access to the HSM key slot used to generate and store keys
   * @param password the pin for the associated HSM slot
   * @throws KeyStoreException error initiating the HSM slot key store
   * @throws CertificateException error parsing certificates in the HSM slot
   * @throws IOException general error processing data
   * @throws NoSuchAlgorithmException algorithm not supported
   */
  public SoftMultiCredentialContainer(Provider provider, String password)
    throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
    super(provider, password);
  }

  @Override public ErasableExternalChainCredential getCredential(String alias) throws PkiCredentialContainerException {
    try {
      return new ErasableExternalChainCredential(new KeyStoreCredential( this.keyStore, alias, this.password), this.keyStore, alias);
    } catch (Exception ex) {
      throw new PkiCredentialContainerException("Error initiating key store credential", ex);
    }
  }

  /**
   * Create the key store used to store generated keys.
   *
   * @param provider the provider for the key store
   * @param password the password for the key store
   * @return key store
   * @throws KeyStoreException error creating the key store
   * @throws CertificateException error loading existing certificates in key store
   * @throws IOException error in input data
   * @throws NoSuchAlgorithmException unsupported algorithm
   */
  @Override protected KeyStore getKeyStore(Provider provider, String password)
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
