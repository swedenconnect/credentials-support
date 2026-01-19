/*
 * Copyright 2020-2026 Sweden Connect
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.swedenconnect.security.credential.PkiCredential;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

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

  /** Logger instance. */
  private static final Logger log = LoggerFactory.getLogger(AbstractKeyStorePkiCredentialContainer.class);

  /** Finder for converting OIDs and AlgorithmIdentifiers into strings. */
  private final static AlgorithmNameFinder algorithmNameFinder = new DefaultAlgorithmNameFinder();

  /** Password for accessing the key store keys. */
  private final char[] password;

  /** The key store instance where all generated keys are stored. */
  private final KeyStore keyStore;

  /** The credentials for this container. */
  private final Map<String, ManagedPkiCredential> credentials = new ConcurrentHashMap<>();

  /**
   * Constructor for the multi credential key store.
   *
   * @param provider the provider that is used to create and manage keys
   * @param password the pin for the associated key container (may be null if a container that does not require a
   *     password is used)
   * @throws KeyStoreException error initiating the key store
   */
  public AbstractKeyStorePkiCredentialContainer(@Nonnull final Provider provider, @Nullable final String password)
      throws KeyStoreException {
    super(provider);
    this.password = Optional.ofNullable(password).map(String::toCharArray).orElse(null);
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
  @Nonnull
  protected abstract KeyStore createKeyStore(@Nonnull final Provider provider, @Nullable final char[] password)
      throws KeyStoreException;

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String generateCredential(@Nonnull final String keyTypeName)
      throws KeyException, NoSuchAlgorithmException, CertificateException {

    final KeyPairGenerator keyPairGenerator =
        this.getKeyGeneratorFactory(keyTypeName).getKeyPairGenerator(this.getProvider());
    final KeyPair keyPair = keyPairGenerator.generateKeyPair();

    final BigInteger alias = this.generateAlias();
    final String aliasString = alias.toString(16);

    final X509Certificate certificate = this.generateKeyCertificate(keyPair, alias);
    try {
      this.keyStore.setKeyEntry(aliasString, keyPair.getPrivate(), null, new Certificate[] { certificate });

      final Consumer<PkiCredential> destroyCallback = (c) -> {
        try {
          this.deleteCredential(aliasString);
        }
        catch (final PkiCredentialContainerException e) {
          log.warn("Failed to remove key entry for alias '{}'", aliasString, e);
        }
      };

      final Consumer<X509Certificate[]> updateCertificatesCallback = (certs) -> {
        try {
          this.keyStore.setKeyEntry(aliasString, keyPair.getPrivate(), null, new Certificate[] { certs[0] });
        }
        catch (final Exception e) {
          log.warn("Failed to update key entry for alias '{}' with new certificate", aliasString, e);
        }
      };

      final ManagedPkiCredential newCredential = new ManagedPkiCredential(
          this.getCredentialFromAlias(aliasString), destroyCallback, updateCertificatesCallback);
      this.credentials.put(aliasString, newCredential);
    }
    catch (final KeyStoreException | PkiCredentialContainerException e) {
      throw new KeyException("Failed to add generated key to keystore - " + e.getMessage(), e);
    }
    return aliasString;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public final ManagedPkiCredential getCredential(@Nonnull final String alias) throws PkiCredentialContainerException {
    final ManagedPkiCredential credential = this.credentials.get(alias);
    if (credential == null) {
      throw new PkiCredentialContainerException("No credential found for alias '" + alias + "'");
    }
    if (this.isExpired(alias)) {
      credential.destroy();
      throw new PkiCredentialContainerException("Requested credential has expired - Destroying credential");
    }
    return credential;
  }

  /**
   * Gets the credential for a specific alias from the credential container.
   *
   * @param alias the alias of the credential to get
   * @return credential for the specified alias
   * @throws PkiCredentialContainerException for errors obtaining the requested credential
   */
  @Nonnull
  protected abstract PkiCredential getCredentialFromAlias(@Nonnull final String alias)
      throws PkiCredentialContainerException;

  /** {@inheritDoc} */
  @Override
  public void deleteCredential(@Nonnull final String alias) throws PkiCredentialContainerException {
    try {
      this.credentials.remove(alias);
      this.keyStore.deleteEntry(alias);
    }
    catch (final KeyStoreException e) {
      throw new PkiCredentialContainerException("Failed to delete " + alias, e);
    }
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public Instant getExpiryTime(@Nonnull final String alias) throws PkiCredentialContainerException {
    final ManagedPkiCredential credential = this.credentials.get(alias);
    if (credential == null) {
      throw new PkiCredentialContainerException("Requested alias is not present");
    }
    return Instant.ofEpochMilli(credential.getCertificate().getNotAfter().getTime());
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public List<String> listCredentials() {
    return this.credentials.keySet().stream().toList();
  }

  /**
   * Gets the password for accessing the key store keys.
   *
   * @return the password
   */
  @Nullable
  protected char[] getPassword() {
    return this.password;
  }

  /**
   * Gets the key store instance where all generated keys are stored.
   *
   * @return the key store
   */
  @Nonnull
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
  @Nonnull
  private X509Certificate generateKeyCertificate(@Nonnull final KeyPair keyPair, @Nonnull final BigInteger alias)
      throws CertificateException {

    try {
      final Date startTime = new Date();
      final Date expiryTime = new Date(System.currentTimeMillis()
          + Optional.ofNullable(this.getKeyValidity())
          .map(Duration::toMillis)
          // 10 years is "forever" for a container
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
  @Nonnull
  protected String getAlgorithmName(@Nonnull final KeyPair keyPair) {
    return keyPair.getPublic() instanceof ECPublicKey
        ? algorithmNameFinder.getAlgorithmName(X9ObjectIdentifiers.ecdsa_with_SHA256)
        : algorithmNameFinder.getAlgorithmName(PKCSObjectIdentifiers.sha256WithRSAEncryption);
  }

  /**
   * Overridable function to produce the issuer and subject name for the self issued certificate. By default, this is a
   * common name that includes the key alias as commonName.
   *
   * @param alias the alias of the key for which the certificate is being issued
   * @return {@link X500Name} representing the alias
   */
  @Nonnull
  protected X500Name getX500Name(@Nonnull final BigInteger alias) {
    return new X500Name(new RDN[] {
        new RDN(new AttributeTypeAndValue(BCStyle.CN, new DERUTF8String(alias.toString(16))))
    });
  }

}
