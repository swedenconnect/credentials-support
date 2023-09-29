/*
 * Copyright 2020-2023 Sweden Connect
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
import java.security.cert.CertificateException;
import java.util.Objects;

import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.pkcs11conf.DefaultPkcs11Configuration;
import se.swedenconnect.security.credential.pkcs11conf.Pkcs11Configuration;
import se.swedenconnect.security.credential.pkcs11conf.Pkcs11ConfigurationException;

/**
 * Implements a {@link PkiCredentialContainer} based on a HSM.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class HsmPkiCredentialContainer extends AbstractKeyStorePkiCredentialContainer {

  /**
   * Constructor for the default PKCS11 credential container where keys are stored in a HSM slot.
   *
   * @param p11Provider the provider that provides access to the HSM key slot used to generate and store keys
   * @param hsmPin the PIN for the associated HSM slot
   * @throws KeyStoreException error initiating the HSM slot key store
   */
  public HsmPkiCredentialContainer(final Provider p11Provider, final String hsmPin) throws KeyStoreException {
    super(p11Provider, Objects.requireNonNull(hsmPin, "hsmPin must not be null"));
  }

  /**
   * Constructor accepting a {@link Pkcs11Configuration} object for getting the PKCS#11 provider.
   *
   * @param p11Configuration the PKCS#11 configuration
   * @param hsmPin the PIN for the HSM slot
   * @throws KeyStoreException error initiating the HSM slot key store
   */
  public HsmPkiCredentialContainer(final Pkcs11Configuration p11Configuration, final String hsmPin)
      throws KeyStoreException {
    this(p11Configuration.getProvider(), hsmPin);
  }

  /**
   * Constructor accepting a PKCS#11 configuration file for getting the PKCS#11 provider.
   *
   * @param p11ConfigurationFile the full path to the PKCS#11 configuration file
   * @param hsmPin the PIN for the HSM slot
   * @throws KeyStoreException error initiating the HSM slot key store
   */
  public HsmPkiCredentialContainer(final String p11ConfigurationFile, final String hsmPin) throws KeyStoreException {
    this(getProviderFromConfigFile(p11ConfigurationFile), hsmPin);
  }

  /** {@inheritDoc} */
  @Override
  protected KeyStore createKeyStore(final Provider provider, final char[] password) throws KeyStoreException {
    try {
      final KeyStore p11KeyStore = KeyStore.getInstance("PKCS11", provider);
      p11KeyStore.load(null, password);
      return p11KeyStore;
    }
    catch (final IOException | NoSuchAlgorithmException | CertificateException e) {
      throw new KeyStoreException("Failed to load PKCS#11 keystore", e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public PkiCredential getCredentialFromAlias(final String alias) throws PkiCredentialContainerException {
    try {
      final KeyStoreCredential cred =
          new KeyStoreCredential(null, "PKCS11", this.getProvider().getName(), this.getPassword(), alias, null);
      cred.init();
      return cred;
    }
    catch (final Exception e) {
      throw new PkiCredentialContainerException("Failed to load PKCS#11 credential", e);
    }
  }

  /**
   * Gets a security provider based on the supplied PKCS#11 configuration file.
   *
   * @param configFile the full path to the PKCS#11 configuration file
   * @return a security provider
   * @throws KeyStoreException for errors initiating the provider
   */
  private static Provider getProviderFromConfigFile(final String configFile) throws KeyStoreException {
    try {
      final DefaultPkcs11Configuration p11Config = new DefaultPkcs11Configuration(configFile);
      p11Config.afterPropertiesSet();
      return p11Config.getProvider();
    }
    catch (final Pkcs11ConfigurationException e) {
      throw new KeyStoreException("Failed to load PKCS#11 provider from " + configFile, e);
    }
  }

}
