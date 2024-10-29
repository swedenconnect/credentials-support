/*
 * Copyright 2020-2024 Sweden Connect
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

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.pkcs11.FilePkcs11Configuration;
import se.swedenconnect.security.credential.pkcs11.Pkcs11Configuration;
import se.swedenconnect.security.credential.pkcs11.Pkcs11ConfigurationException;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.util.Objects;

/**
 * Implements a {@link PkiCredentialContainer} based on an HSM.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class HsmPkiCredentialContainer extends AbstractKeyStorePkiCredentialContainer {

  /**
   * Constructor for the default PKCS11 credential container where keys are stored in an HSM slot.
   *
   * @param p11Provider the provider that provides access to the HSM key slot used to generate and store keys
   * @param hsmPin the PIN for the associated HSM slot
   * @throws KeyStoreException error initiating the HSM slot key store
   */
  public HsmPkiCredentialContainer(@Nonnull final Provider p11Provider, @Nonnull final String hsmPin)
      throws KeyStoreException {
    super(p11Provider, Objects.requireNonNull(hsmPin, "hsmPin must not be null"));
  }

  /**
   * Constructor accepting a {@link Pkcs11Configuration} object for getting the PKCS#11 provider.
   *
   * @param p11Configuration the PKCS#11 configuration
   * @param hsmPin the PIN for the HSM slot
   * @throws KeyStoreException error initiating the HSM slot key store
   */
  public HsmPkiCredentialContainer(@Nonnull final Pkcs11Configuration p11Configuration, @Nonnull final String hsmPin)
      throws KeyStoreException {
    this(Objects.requireNonNull(p11Configuration, "p11Configuration must not be null").getProvider(), hsmPin);
  }

  /**
   * Constructor accepting a PKCS#11 configuration file for getting the PKCS#11 provider.
   *
   * @param p11ConfigurationFile the full path to the PKCS#11 configuration file
   * @param hsmPin the PIN for the HSM slot
   * @throws KeyStoreException error initiating the HSM slot key store
   */
  public HsmPkiCredentialContainer(@Nonnull final String p11ConfigurationFile, @Nonnull final String hsmPin)
      throws KeyStoreException {
    this(getProviderFromConfigFile(
        Objects.requireNonNull(p11ConfigurationFile, "p11ConfigurationFile must not be null")), hsmPin);
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected KeyStore createKeyStore(@Nonnull final Provider provider, @Nullable final char[] password)
      throws KeyStoreException {
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
  @Nonnull
  public PkiCredential getCredentialFromAlias(@Nonnull final String alias) throws PkiCredentialContainerException {
    try {
      final KeyStoreCredential credential = new KeyStoreCredential(this.getKeyStore(), alias, this.getPassword());
      credential.setName(alias);
      return credential;
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
  @Nonnull
  private static Provider getProviderFromConfigFile(@Nonnull final String configFile) throws KeyStoreException {
    try {
      final FilePkcs11Configuration p11Configuration = new FilePkcs11Configuration(configFile);
      p11Configuration.init();
      return p11Configuration.getProvider();
    }
    catch (final Pkcs11ConfigurationException e) {
      throw new KeyStoreException("Failed to load PKCS#11 provider from " + configFile, e);
    }
  }

}
