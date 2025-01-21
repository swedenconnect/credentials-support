/*
 * Copyright 2020-2025 Sweden Connect
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
package se.swedenconnect.security.credential;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.swedenconnect.security.credential.factory.KeyStoreFactory;
import se.swedenconnect.security.credential.monitoring.DefaultCredentialTestFunction;
import se.swedenconnect.security.credential.pkcs11.Pkcs11KeyStoreReloader;

import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * A {@link java.security.KeyStore} implementation of the {@link se.swedenconnect.security.credential.PkiCredential} and
 * {@link se.swedenconnect.security.credential.ReloadablePkiCredential} interfaces.
 * <p>
 * The constructors expect a loaded, and unlocked, {@link java.security.KeyStore}. See
 * {@link se.swedenconnect.security.credential.factory.KeyStoreFactory} for methods to load a {@link KeyStore}.
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class KeyStoreCredential extends AbstractReloadablePkiCredential {

  /** Logger **/
  private static final Logger log = LoggerFactory.getLogger(KeyStoreCredential.class);

  /** The keystore. */
  private final KeyStore keyStore;

  /** The alias to the entry holding the key pair. */
  private final String alias;

  /** the password to unlock the private key. */
  private final char[] keyPassword;

  /** Certificates for the credential. */
  private final List<X509Certificate> certificates;

  /** Whether this is a hardware credential or not. */
  private final boolean residesInHardware;

  /** For reloading the keystore. */
  private KeyStoreReloader reloader;

  /**
   * Constructor taking a {@link KeyStore} and the key entry alias and a key password.
   *
   * @param keyStore the keystore to read the key pair from
   * @param alias the alias to the entry holding the key pair
   * @param keyPassword the password to unlock the key pair (may be {@code null})
   * @throws KeyStoreException for errors loading the contents
   */
  public KeyStoreCredential(@Nonnull final KeyStore keyStore, @Nonnull final String alias,
      @Nullable final char[] keyPassword) throws KeyStoreException {
    this(keyStore, alias, keyPassword, null);
  }

  /**
   * When using a PKCS#11 {@link KeyStore} a variant is to only access the private key from the HSM, and have the
   * corresponding certificate stored outside the HSM. This constructor creates an instance where certificates are not
   * read from the {@link KeyStore}.
   *
   * @param keyStore the keystore to read the key pair from
   * @param alias the alias to the entry holding the key pair
   * @param keyPassword the password to unlock the key pair (may be {@code null})
   * @param certificateChain a non-empty list of certificates, where the entity certificate must be placed first in
   *     the list
   * @throws KeyStoreException for errors loading the contents
   */
  public KeyStoreCredential(
      @Nonnull final KeyStore keyStore, @Nonnull final String alias, @Nullable final char[] keyPassword,
      @Nullable final List<X509Certificate> certificateChain) throws KeyStoreException {

    this.keyStore = Objects.requireNonNull(keyStore, "keyStore must not be null");
    this.alias = Objects.requireNonNull(alias, "alias must not be null");
    if (keyPassword != null) {
      this.keyPassword = new char[keyPassword.length];
      System.arraycopy(keyPassword, 0, this.keyPassword, 0, keyPassword.length);
    }
    else {
      this.keyPassword = null;
    }

    this.residesInHardware = KeyStoreFactory.PKCS11_KEYSTORE_TYPE.equalsIgnoreCase(this.keyStore.getType());

    // Install a default test function - this may be overridden by setTestFunction later ...
    if (this.residesInHardware) {
      final DefaultCredentialTestFunction testFunction = new DefaultCredentialTestFunction();
      testFunction.setProvider(Optional.ofNullable(this.keyStore.getProvider()).map(Provider::getName).orElse(null));
      this.setTestFunction(testFunction);
    }

    // Assert that everything looks good by loading the key and certificate ...
    //
    this.getPrivateKey();
    if (certificateChain == null) {
      this.certificates = this.loadCertificateChain();
    }
    else {
      this.certificates = Collections.unmodifiableList(certificateChain);
      if (this.certificates.isEmpty()) {
        throw new IllegalArgumentException("certificateChain must not be empty");
      }
    }

    // Finally, update metadata properties with settings for issued-at and expires-at ...
    //
    this.updateMetadataValidityProperties();
  }

  /**
   * Returns the underlying {@link KeyStore}.
   *
   * @return the {@link KeyStore}
   */
  @Nonnull
  public KeyStore getKeyStore() {
    return this.keyStore;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public synchronized PrivateKey getPrivateKey() {
    try {
      final Key key = this.keyStore.getKey(this.alias, this.keyPassword);

      if (key instanceof final PrivateKey privateKey) {
        return privateKey;
      }
      else {
        throw new SecurityException("No private key entry found for '%s'".formatted(this.alias));
      }
    }
    catch (final KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException e) {
      throw new SecurityException(e);
    }
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public List<X509Certificate> getCertificateChain() {
    return this.certificates;
  }

  @PreDestroy
  public void destroy() {
    if (this.keyPassword != null) {
      Arrays.fill(this.keyPassword, (char) 0);
    }
  }

  /** {@inheritDoc} */
  @Override
  public boolean isHardwareCredential() {
    return this.residesInHardware;
  }

  /**
   * Loads the certificate chain from the {@link KeyStore}.
   *
   * @return a list of certificates
   * @throws KeyStoreException for error loading the certificates
   */
  @Nonnull
  private List<X509Certificate> loadCertificateChain() throws KeyStoreException {
    final Object[] chain = this.keyStore.getCertificateChain(this.alias);
    if (chain == null || chain.length == 0) {
      // Just to be sure. Some P11 implementations may not handle chains...
      final X509Certificate cert = (X509Certificate) this.keyStore.getCertificate(this.alias);
      if (cert == null) {
        throw new KeyStoreException("No certificate found at entry " + this.alias);
      }
      return Collections.singletonList(cert);
    }
    else {
      return Arrays.stream(chain)
          .map(X509Certificate.class::cast)
          .toList();
    }
  }

  /**
   * Assigns a {@link KeyStoreReloader} for supporting reload of a hardware based credential.
   *
   * @param reloader the reloader instance
   */
  public void setReloader(@Nonnull final KeyStoreReloader reloader) {
    this.reloader = reloader;
  }

  /**
   * Returns the key store reloader and creates a default one if it has not been installed (for hardware tokens).
   *
   * @return the {@link KeyStoreReloader}
   */
  private synchronized KeyStoreReloader getReloader() {
    if (this.reloader == null && this.isHardwareCredential()) {
      this.reloader = new Pkcs11KeyStoreReloader(this.keyPassword);
    }
    return this.reloader;
  }

  /**
   * If the {@code KeyStoreCredential} is of PKCS#11 type, and a {@link KeyStoreReloader} has been installed, the method
   * will reload the private key.
   */
  @Override
  public synchronized void reload() throws Exception {
    //
    // Note: We log only on trace level since the monitor driving the reloading is responsible
    // for the actual logging.
    //
    // Reload ...
    //
    final KeyStoreReloader keyStoreReloader = this.getReloader();
    if (keyStoreReloader != null) {
      try {
        log.trace("Reloading private key of credential '{}' ...", this.getName());
        keyStoreReloader.reload(this.keyStore);

        // Now, access the private key ...
        this.getPrivateKey();

        log.trace("Reloading private key of credential '{}' successful", this.getName());
      }
      catch (final Exception e) {
        log.trace("Failed to reload private key - {}", e.getMessage(), e);
        throw e;
      }
    }
    else if (this.isHardwareCredential()) {
      throw new SecurityException("No reload function installed for credential '%s'".formatted(this.getName()));
    }
  }

  /** {@inheritDoc} */
  @Nonnull
  @Override
  protected String getDefaultName() {
    if (KeyStoreFactory.PKCS11_KEYSTORE_TYPE.equalsIgnoreCase(this.keyStore.getType())) {
      return "%s-%s-%s".formatted(this.keyStore.getProvider().getName(), this.alias,
          this.getCertificate().getSerialNumber().toString(10));
    }
    else {
      return "%s-%s-%s".formatted(this.getPublicKey().getAlgorithm(), this.alias,
          this.getCertificate().getSerialNumber().toString(10));
    }
  }

}
