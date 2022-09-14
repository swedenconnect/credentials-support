package se.swedenconnect.security.credential.container;

import lombok.Setter;
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
import se.swedenconnect.security.credential.container.exceptions.PkiCredentialContainerException;
import se.swedenconnect.security.credential.container.keytype.KeyGenType;
import se.swedenconnect.security.credential.container.keytype.KeyPairGeneratorFactory;
import se.swedenconnect.security.credential.utils.X509Utils;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * Abstract implementation of the {@link PkiCredentialContainer} interface
 *
 * <p>
 *   This abstract implementation implements all functions that can be implemented independent of whether
 *   the actual key store is provided in software or in a HSM
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public abstract class AbstractPkiCredentialContainer implements PkiCredentialContainer {

  /** Finder for converting OIDs and AlgorithmIdentifiers into strings. */
  protected final static AlgorithmNameFinder algorithmNameFinder = new DefaultAlgorithmNameFinder();

  /** The provider for the key store where generated keys are stored */
  protected final Provider provider;

  /** Password for accessing the key store keys */
  protected final char[] password;

  /** The key store instance where all generated keys are stored */
  protected final KeyStore keyStore;

  /** The duration for which all generated keys are valid */
  @Setter private Duration keyDuration;

  /** List of key generator initiators for supported key types */
  @Setter List<KeyPairGeneratorFactory> supportedKeyGenerators;

  /** Random source for generating unique key aliases */
  private final SecureRandom RNG = new SecureRandom();

  /**
   * Constructor for the multi credential key store
   *
   * @param provider the provider that is used to create and manage keys
   * @param password the pin for the associated key container
   * @throws KeyStoreException error initiating the key store
   */
  public AbstractPkiCredentialContainer(final @Nonnull Provider provider, final @Nonnull String password)
    throws KeyStoreException {
    Objects.requireNonNull(provider, "Provider must not be null");
    Objects.requireNonNull(password, "Password must not be null");
    this.provider = provider;
    this.password = password.toCharArray();
    this.keyStore = getKeyStore(provider, password);
    this.supportedKeyGenerators = getDefaultKeyGenerators();
    this.keyDuration = Duration.ofMinutes(15);
  }

  /**
   * Create the key store used to store generated keys.
   *
   * @param provider the provider for the key store
   * @param password the password for the key store
   * @return key store
   * @throws KeyStoreException error creating the key store
   */
  protected abstract KeyStore getKeyStore(final @Nonnull Provider provider, final String password)
    throws KeyStoreException;

  /**
   * Function to provide the default list of key generator initiators for generated keys
   *
   * @return list of {@link KeyPairGeneratorFactory} for each supported key type
   */
  protected List<KeyPairGeneratorFactory> getDefaultKeyGenerators() {
    return List.of(
      KeyGenType.EC_P256_Factory,
      KeyGenType.EC_P384_Factory,
      KeyGenType.EC_P521_Factory,
      KeyGenType.RSA_3072_Factory,
      KeyGenType.RSA_4096_Factory
    );
  }

  /**
   * Overridable function to generate the unique alias for each generated key. The key alias must be a BigInteger
   * as it is used both as alias, but also as serial number for the associated self-issued certificate
   *
   * @return {@link BigInteger} key alias
   */
  protected BigInteger getAlias() {
    return new BigInteger(64, RNG);
  }

  /** {@inheritDoc} */
  @Override
  public String generateCredential(final @Nonnull String keyTypeName)
    throws KeyException, NoSuchAlgorithmException, CertificateException {
    Objects.requireNonNull(keyTypeName, "Key type name must not be null");

    KeyPairGeneratorFactory keyPairGeneratorFactory = getKeyGenInitiator(keyTypeName);
    BigInteger alias = getAlias();
    String aliasStr = alias.toString(16);
    KeyPairGenerator keyPairGenerator = keyPairGeneratorFactory.getKeyPairGenerator(provider);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    X509Certificate certificate = generateKeyCertificate(keyPair, alias);
    try {
      keyStore.setKeyEntry(aliasStr, keyPair.getPrivate(), null,new Certificate[]{certificate});
    }
    catch (KeyStoreException e) {
      throw new KeyException(e);
    }
    return aliasStr;
  }

  /** {@inheritDoc} */
  @Override
  public void deleteCredential(String alias) throws PkiCredentialContainerException {
    Objects.requireNonNull(alias, "Key alias must not be null");
    try {
      keyStore.deleteEntry(alias);
    }
    catch (KeyStoreException e) {
      throw new PkiCredentialContainerException(e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public Instant getExpiryTime(String alias) throws PkiCredentialContainerException {
    Objects.requireNonNull(alias, "Key alias must not be null");
    if (!getAvailableCredentials().contains(alias)){
      throw new PkiCredentialContainerException("Requested alias is not present");
    }
    try {
      X509Certificate certificate = X509Utils.decodeCertificate(keyStore.getCertificate(alias).getEncoded());
      return Instant.ofEpochMilli(certificate.getNotAfter().getTime());
    }
    catch (CertificateException | KeyStoreException e) {
      throw new PkiCredentialContainerException("Unable to retrieve a valid certificate", e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public List<String> getAvailableCredentials() throws PkiCredentialContainerException {
    try {
      return Collections.list(keyStore.aliases());
    }
    catch (KeyStoreException e) {
      throw new PkiCredentialContainerException(e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public void cleanup() throws PkiCredentialContainerException {
    List<String> deleteList = new ArrayList<>();
    List<String> credentialAliasList = getAvailableCredentials();

    for (String alias : credentialAliasList) {
      if (getExpiryTime(alias).isBefore(Instant.now())) {
        deleteList.add(alias);
      }

      for (String deleteAlias : deleteList) {
        deleteCredential(deleteAlias);
      }
    }
  }


  private KeyPairGeneratorFactory getKeyGenInitiator(final String keyTypeName) throws NoSuchAlgorithmException {
    return supportedKeyGenerators.stream()
      .filter(keyGeneratorInitiator -> keyGeneratorInitiator.supports(keyTypeName))
      .findFirst()
      .orElseThrow(NoSuchAlgorithmException::new);
  }

  private X509Certificate generateKeyCertificate(final KeyPair kp, final BigInteger alias)
    throws CertificateException {

    try {
      Date startTime = new Date();
      Date expiryTime = new Date(System.currentTimeMillis() + keyDuration.toMillis());
      X500Name issuerSubject = this.getX500Name(alias);

      final JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
        issuerSubject,
        alias,
        startTime,
        expiryTime,
        issuerSubject,
        kp.getPublic());

      return CertUtil.decodeCertificate(certificateBuilder.build(
        new JcaContentSignerBuilder(this.getAlgorithmName(kp)).build(kp.getPrivate())).getEncoded());
    }
    catch (EncodingException | IOException | OperatorCreationException e) {
      throw new CertificateException(e);
    }
  }

  /**
   * Overridable function to provide the certificate signing JCA algorithm name of the algorithm used to
   * sign the self-signed certificate associated with a generated key.
   *
   * @param keyPair  generated key pair
   * @return the JCA algorithm name suitable for used with the key pair
   */
  protected String getAlgorithmName(final KeyPair keyPair) {
    return  (keyPair.getPublic() instanceof ECPublicKey)
      ? algorithmNameFinder.getAlgorithmName(X9ObjectIdentifiers.ecdsa_with_SHA256)
      : algorithmNameFinder.getAlgorithmName(PKCSObjectIdentifiers.sha256WithRSAEncryption);
  }

  /**
   * Overridable function to produce the issuer and subject name for the self issued certificate. By default
   * this is a common name that includes the key alias as commonName
   *
   * @param alias the alias of the key for which the certificate is being issued
   * @return {@link X500Name} representing the alias
   */
  protected X500Name getX500Name(final BigInteger alias) {
    return new X500Name(new RDN[]{
      new RDN(new AttributeTypeAndValue(BCStyle.CN, new DERUTF8String(alias.toString(16))))
    });
  }

}

