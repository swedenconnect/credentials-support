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
import java.math.BigInteger;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.AlgorithmNameFinder;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cryptacular.EncodingException;
import org.cryptacular.util.CertUtil;
import org.springframework.beans.factory.DisposableBean;

import se.swedenconnect.security.credential.AbstractReloadablePkiCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.ReloadablePkiCredential;
import se.swedenconnect.security.credential.utils.X509Utils;

/**
 * Abstract implementation of the {@link PkiCredentialContainer} interface for implementations that rely on an
 * underlying Java KeyStore.
 * <p>
 * This abstract implementation implements all functions that can be implemented independent of whether the actual key
 * store is provided in software or in a HSM.
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public abstract class AbstractKeyStorePkiCredentialContainer extends AbstractPkiCredentialContainer {

  /** Finder for converting OIDs and AlgorithmIdentifiers into strings. */
  private final static AlgorithmNameFinder algorithmNameFinder = new DefaultAlgorithmNameFinder();

  /** Password for accessing the key store keys. */
  private final char[] password;

  /** The key store instance where all generated keys are stored. */
  private final KeyStore keyStore;

  /**
   * Constructor for the multi credential key store.
   *
   * @param provider the provider that is used to create and manage keys
   * @param password the pin for the associated key container (may be null if a container that does not require a
   *          password is used)
   * @throws KeyStoreException error initiating the key store
   */
  public AbstractKeyStorePkiCredentialContainer(final Provider provider, final String password)
      throws KeyStoreException {
    super(provider);
    this.password = Optional.ofNullable(password).map(p -> p.toCharArray()).orElse(null);
    this.keyStore = this.createKeyStore(provider, this.password);
  }

  /**
   * Creates the key store used to store generated keys.
   *
   * @param provider the provider for the key store
   * @param password the password for the key store
   * @return key store
   * @throws KeyStoreException error creating the key store
   */
  protected abstract KeyStore createKeyStore(final Provider provider, final char[] password) throws KeyStoreException;

  /** {@inheritDoc} */
  @Override
  public String generateCredential(final String keyTypeName)
      throws KeyException, NoSuchAlgorithmException, CertificateException {

    final KeyPairGenerator keyPairGenerator =
        this.getKeyGeneratorFactory(keyTypeName).getKeyPairGenerator(this.getProvider());
    final KeyPair keyPair = keyPairGenerator.generateKeyPair();

    final BigInteger alias = this.generateAlias();
    final String aliasString = alias.toString(16);

    final X509Certificate certificate = this.generateKeyCertificate(keyPair, alias);
    try {
      this.keyStore.setKeyEntry(aliasString, keyPair.getPrivate(), null, new Certificate[] { certificate });
    }
    catch (final KeyStoreException e) {
      throw new KeyException("Failed to add generated key to keystore - " + e.getMessage(), e);
    }
    return aliasString;
  }

  /** {@inheritDoc} */
  @Override
  public final PkiCredential getCredential(final String alias) throws PkiCredentialContainerException {
    final PkiCredential credential = this.getCredentialFromAlias(alias);
    final PkiCredential disposableCredential = new DisposableKeyStoreCredential(credential, this.keyStore, alias);
    if (this.isExpired(alias)) {
      try {
        disposableCredential.destroy();
        throw new PkiCredentialContainerException("Requested credential has expired - Destroying credential");
      }
      catch (final Exception e) {
        throw PkiCredentialContainerException.class.isInstance(e)
            ? (PkiCredentialContainerException) e
            : new PkiCredentialContainerException("Failure to destroy expired credential", e);
      }
    }
    return disposableCredential;
  }

  /**
   * Gets the credential for a specific alias from the credential container.
   *
   * @param alias the alias of the credential to get
   * @return credential for the specified alias
   * @throws PkiCredentialContainerException for errors obtaining the requested credential
   */
  protected abstract PkiCredential getCredentialFromAlias(final String alias) throws PkiCredentialContainerException;

  /** {@inheritDoc} */
  @Override
  public void deleteCredential(final String alias) throws PkiCredentialContainerException {
    try {
      this.keyStore.deleteEntry(alias);
    }
    catch (final KeyStoreException e) {
      throw new PkiCredentialContainerException("Failed to delete " + alias, e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public Instant getExpiryTime(final String alias) throws PkiCredentialContainerException {
    if (!this.listCredentials().contains(alias)) {
      throw new PkiCredentialContainerException("Requested alias is not present");
    }
    try {
      final X509Certificate certificate = X509Utils.decodeCertificate(this.keyStore.getCertificate(alias).getEncoded());
      return Instant.ofEpochMilli(certificate.getNotAfter().getTime());
    }
    catch (CertificateException | KeyStoreException e) {
      throw new PkiCredentialContainerException("Unable to retrieve a valid certificate", e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public List<String> listCredentials() throws PkiCredentialContainerException {
    try {
      return Collections.list(this.keyStore.aliases());
    }
    catch (final KeyStoreException e) {
      throw new PkiCredentialContainerException("Failed to list aliases", e);
    }
  }

  /**
   * Gets the password for accessing the key store keys.
   *
   * @return the password
   */
  protected char[] getPassword() {
    return this.password;
  }

  /**
   * Gets the key store instance where all generated keys are stored.
   *
   * @return the key store
   */
  protected KeyStore getKeyStore() {
    return this.keyStore;
  }

  /**
   * Generates a self-signed certificate.
   *
   * @param keyPair the key pair
   * @param alias alias used both as CN and serialnumber
   * @return a X509Certificate
   * @throws CertificateException for errors during the certificate creation
   */
  private X509Certificate generateKeyCertificate(final KeyPair keyPair, final BigInteger alias)
      throws CertificateException {

    try {
      final Date startTime = new Date();
      final Date expiryTime = new Date(System.currentTimeMillis()
          + Optional.ofNullable(this.getKeyValidity())
              .map(Duration::toMillis)
              // 10 years is "for ever" for a container
              .orElseGet(() -> Duration.ofDays(3650).toMillis()));
      final X500Name issuerSubject = this.getX500Name(alias);

      final JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
          issuerSubject,
          alias,
          startTime,
          expiryTime,
          issuerSubject,
          keyPair.getPublic());

      return CertUtil.decodeCertificate(certificateBuilder.build(
          new JcaContentSignerBuilder(this.getAlgorithmName(keyPair)).build(keyPair.getPrivate())).getEncoded());
    }
    catch (final EncodingException | IOException | OperatorCreationException e) {
      throw new CertificateException("Error generating certificate - " + e.getMessage(), e);
    }
  }

  /**
   * Overridable method to provide the certificate signing JCA algorithm name of the algorithm used to sign the
   * self-signed certificate associated with a generated key.
   *
   * @param keyPair generated key pair
   * @return the JCA algorithm name suitable for used with the key pair
   */
  protected String getAlgorithmName(final KeyPair keyPair) {
    return keyPair.getPublic() instanceof ECPublicKey
        ? algorithmNameFinder.getAlgorithmName(X9ObjectIdentifiers.ecdsa_with_SHA256)
        : algorithmNameFinder.getAlgorithmName(PKCSObjectIdentifiers.sha256WithRSAEncryption);
  }

  /**
   * Overridable function to produce the issuer and subject name for the self issued certificate. By default this is a
   * common name that includes the key alias as commonName.
   *
   * @param alias the alias of the key for which the certificate is being issued
   * @return {@link X500Name} representing the alias
   */
  protected X500Name getX500Name(final BigInteger alias) {
    return new X500Name(new RDN[] {
        new RDN(new AttributeTypeAndValue(BCStyle.CN, new DERUTF8String(alias.toString(16))))
    });
  }

  /**
   * The credentials returned from the container's {@link PkiCredentialContainer#getCredential(String)} all implement
   * {@link DisposableBean} meaning that the {@code destroy} method may be invoked. If this happens we want the
   * credential to be removed from our loaded keystore.
   *
   * @author Martin Lindström (martin@idsec.se)
   * @author Stefan Santesson (stefan@idsec.se)
   */
  private static class DisposableKeyStoreCredential extends AbstractReloadablePkiCredential {

    /** The wrapped credential. */
    private final PkiCredential credential;

    /** Key store used to manage the key and primary certificate of the credential. */
    private final KeyStore keyStore;

    /** Alias of the credential key and certificate in the key store. */
    private final String alias;

    /** Flag used to avoid executing destruction several times. */
    private boolean destroyed = false;

    /**
     * Constructor.
     *
     * @param credential the wrapped credential
     * @param keyStore the keystore
     * @param alias the alias pointing at the keystore entry holding the credential
     */
    public DisposableKeyStoreCredential(final PkiCredential credential, final KeyStore keyStore, final String alias) {
      this.credential = Objects.requireNonNull(credential, "credential must not be null");
      this.keyStore = Objects.requireNonNull(keyStore, "keyStore must not be null");
      this.alias = Objects.requireNonNull(alias, "alias must not be null");
    }

    /** {@inheritDoc} */
    @Override
    public PublicKey getPublicKey() {
      return this.credential.getPublicKey();
    }

    /** {@inheritDoc} */
    @Override
    public void setPublicKey(final PublicKey publicKey) {
      throw new IllegalArgumentException("Can not assign public key to DisposableKeyStoreCredential");
    }

    /** {@inheritDoc} */
    @Override
    public X509Certificate getCertificate() {
      return this.credential.getCertificate();
    }

    /** {@inheritDoc} */
    @Override
    public void setCertificate(final X509Certificate x509Certificate) {
      this.credential.setCertificate(x509Certificate);
    }

    /** {@inheritDoc} */
    @Override
    public List<X509Certificate> getCertificateChain() {
      return this.credential.getCertificateChain();
    }

    /** {@inheritDoc} */
    @Override
    public void setCertificateChain(final List<X509Certificate> certificateChain) {
      this.credential.setCertificateChain(certificateChain);
    }

    /** {@inheritDoc} */
    @Override
    public PrivateKey getPrivateKey() {
      return this.credential.getPrivateKey();
    }

    /** {@inheritDoc} */
    @Override
    public void setPrivateKey(final PrivateKey privateKey) {
      throw new IllegalArgumentException("Can not assign private key to DisposableKeyStoreCredential");
    }

    /** {@inheritDoc} */
    @Override
    public void reload() throws Exception {
      if (ReloadablePkiCredential.class.isInstance(this.credential)) {
        ReloadablePkiCredential.class.cast(this.credential).reload();
      }
    }

    /** {@inheritDoc} */
    @Override
    protected String getDefaultName() {
      return this.alias;
    }

    /**
     * Removes the credential key entry from the contained key store.
     */
    @Override
    public void destroy() throws Exception {
      if (!destroyed) {
        this.destroyed = true;
        this.credential.destroy();
        // There may be several credential objects connecting to the same alias.
        // Suppose that two thread both invoke getCredential for the same alias (odd case, both possible).
        // In those cases the destroy() method will be invoked twice for the same entry. Therefore
        // we ensure that the entry exists before attempting to delete it.
        //
        if (this.keyStore.containsAlias(alias)) {
          this.keyStore.deleteEntry(this.alias);
        }
      }
    }

  }

}
