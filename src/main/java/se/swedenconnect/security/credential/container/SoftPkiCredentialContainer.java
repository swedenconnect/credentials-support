/*
 * Copyright 2020-2022 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.swedenconnect.security.credential.container;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;

import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * Implements a {@link PkiCredentialContainer} based on a {@link KeyStore} that is held in memory (i.e. not using a HSM
 * device for key storage).
 * <p>
 * Also see {@link InMemoryPkiCredentialContainer} that is an in-memory container that does not
 * use key stores (and thus, does not generate any certificates as part of the key generation process).
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class SoftPkiCredentialContainer extends AbstractKeyStorePkiCredentialContainer {

  /**
   * Constructor loading the security provider identified by {@code providerName}. No password is used for the generated
   * key store.
   *
   * @param providerName the name of the security provider
   * @throws KeyStoreException for errors creating the key store
   */
  public SoftPkiCredentialContainer(final String providerName) throws KeyStoreException {
    this(providerName, null);
  }

  /**
   * Constructor. No password is used for the generated key store.
   *
   * @param provider the security provider
   * @throws KeyStoreException for errors creating the key store
   */
  public SoftPkiCredentialContainer(final Provider provider) throws KeyStoreException {
    this(provider, null);
  }

  /**
   * Constructor loading the security provider identified by {@code providerName}.
   *
   * @param providerName the name of the security provider
   * @param password the store password that we should use for the generated key store (may be null)
   * @throws KeyStoreException for errors creating the key store
   */
  public SoftPkiCredentialContainer(final String providerName, final String password) throws KeyStoreException {
    super(Security.getProvider(providerName), password);
  }

  /**
   * Constructor.
   *
   * @param provider the security provider
   * @param password the store password that we should use for the generated key store (may be null)
   * @throws KeyStoreException for errors creating the key store
   */
  public SoftPkiCredentialContainer(final Provider provider, final String password) throws KeyStoreException {
    super(provider, password);
  }

  /** {@inheritDoc} */
  @Override
  protected KeyStore createKeyStore(final Provider provider, final char[] password) throws KeyStoreException {
    try {
      final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType(), provider);
      keyStore.load(null, password);
      return keyStore;
    }
    catch (final IOException | NoSuchAlgorithmException | CertificateException e) {
      throw new KeyStoreException("Failed to create keystore", e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public PkiCredential getCredentialFromAlias(final String alias) throws PkiCredentialContainerException {
    try {
      final KeyStoreCredential credential = new KeyStoreCredential(this.getKeyStore(), alias, this.getPassword());
      credential.init();
      return credential;
    }
    catch (final Exception e) {
      throw new PkiCredentialContainerException("Error initiating key store credential", e);
    }
  }

}
