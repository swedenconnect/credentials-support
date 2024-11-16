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
package se.swedenconnect.security.credential.factory;

import jakarta.annotation.Nonnull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.config.AbstractFactoryBean;
import org.springframework.core.io.Resource;
import org.springframework.util.StringUtils;
import se.swedenconnect.security.credential.AbstractPkiCredential;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.pkcs11.FilePkcs11Configuration;
import se.swedenconnect.security.credential.utils.KeyUtils;
import se.swedenconnect.security.credential.utils.X509Utils;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * A utility factory that can create any type of {@link PkiCredential}.
 * <p>
 * This implementation will be removed in future releases. Consider using {@link PkiCredentialFactory} or
 * {@link se.swedenconnect.security.credential.spring.factory.PkiCredentialFactoryBean} instead.
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 * @deprecated Use {@link PkiCredentialFactory} or
 *     {@link se.swedenconnect.security.credential.spring.factory.PkiCredentialFactoryBean} instead.
 */
@Deprecated(since = "2.0.0", forRemoval = true)
public class PkiCredentialFactoryBean extends AbstractFactoryBean<PkiCredential> {

  /** Logger instance. */
  private static final Logger log = LoggerFactory.getLogger(PkiCredentialFactoryBean.class);

  /** The name of the credential. */
  private String name;

  /**
   * A resource holding the certificate part of the credential (optional since the certificate may be part of a
   * keystore).
   */
  private Resource certificate;

  /**
   * A list of resources holding the certificate chain that part of the credential (optional since the certificate may
   * be part of a keystore). If used, the entity certificate must be the first element.
   */
  private List<Resource> certificates;

  /** A resource holding the private key part of the credential (optional since the key may be part of a keystore). */
  private Resource privateKey;

  /** A resource to the keystore containing the credential. */
  private Resource resource;

  /** The keystore password. */
  private char[] password;

  /** The type of keystore. */
  private String type;

  /** The name of the security provider to use when creating the KeyStore instance. */
  private String provider;

  /** The PKCS#11 configuration file to use. */
  private String pkcs11Configuration;

  /** The keystore alias to the entry holding the key pair. */
  private String alias;

  /** The password to unlock the private key from the keystore. */
  private char[] keyPassword;

  /**
   * Default constructor.
   */
  public PkiCredentialFactoryBean() {
  }

  /**
   * Constructor that initializes the factory from the supplied credential configuration properties object.
   *
   * @param properties credential configuration properties
   */
  public PkiCredentialFactoryBean(final PkiCredentialConfigurationProperties properties) {
    this.setName(properties.getName());
    if (properties.getCertificate() != null) {
      this.setCertificate(properties.getCertificate());
    }
    if (properties.getCertificates() != null) {
      this.setCertificates(properties.getCertificates());
    }
    this.setPrivateKey(properties.getPrivateKey());
    this.setResource(properties.getResource());
    this.setPassword(properties.getPassword());
    this.setType(properties.getType());
    this.setProvider(properties.getProvider());
    this.setPkcs11Configuration(properties.getPkcs11Configuration());
    this.setAlias(properties.getAlias());
    this.setKeyPassword(properties.getKeyPassword());
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected PkiCredential createInstance() throws Exception {

    AbstractPkiCredential credential = null;

    final List<X509Certificate> _certificates = new ArrayList<>();
    if (this.certificates != null && !this.certificates.isEmpty()) {
      for (final Resource r : this.certificates) {
        try (final InputStream is = r.getInputStream()) {
          _certificates.add(X509Utils.decodeCertificate(is));
        }
      }
    }
    else if (this.certificate != null) {
      try (final InputStream is = this.certificate.getInputStream()) {
        _certificates.add(X509Utils.decodeCertificate(is));
      }
    }

    if (!_certificates.isEmpty() && this.privateKey != null) {
      try (final InputStream is = this.privateKey.getInputStream()) {
        final PrivateKey pk = KeyUtils.decodePrivateKey(is, this.keyPassword);
        credential = new BasicCredential(_certificates, pk);
      }
    }
    else if (StringUtils.hasText(this.pkcs11Configuration) && StringUtils.hasText(this.alias)
        && (this.keyPassword != null || this.password != null)
        && (!StringUtils.hasText(this.type) || "PKCS11".equalsIgnoreCase(this.type))) {

      final char[] pin = this.keyPassword != null ? this.keyPassword : this.password;
      final FilePkcs11Configuration p11Configuration = new FilePkcs11Configuration(this.pkcs11Configuration);

      final KeyStore ks = KeyStoreFactory.loadPkcs11KeyStore(p11Configuration, pin);
      credential = new KeyStoreCredential(ks, this.alias, pin, _certificates.isEmpty() ? null : _certificates);
    }
    else if (this.resource != null && this.password != null && this.alias != null) {
      try (final InputStream is = this.resource.getInputStream()) {
        final KeyStore ks = KeyStoreFactory.loadKeyStore(is, this.password, this.type, this.provider);
        credential =
            new KeyStoreCredential(ks, this.alias, this.keyPassword != null ? this.keyPassword : this.password);
      }
    }

    if (credential == null) {
      // If afterPropertiesSet is called, we'll never end up here ...
      throw new SecurityException("PkiCredentialFactoryBean was not correctly configured");
    }

    // Assign the name (if set) ...
    if (StringUtils.hasText(this.name)) {
      credential.setName(this.name);
    }

    return credential;
  }

  /** {@inheritDoc} */
  @Override
  public Class<?> getObjectType() {
    return PkiCredential.class;
  }

  /**
   * Assigns the name of the credential.
   *
   * @param name the credential name
   */
  public void setName(final String name) {
    this.name = name;
  }

  /**
   * Assigns the resource holding the certificate part of the credential (optional since the certificate may be part of
   * a keystore).
   *
   * @param certificate certificate resource
   */
  public void setCertificate(final Resource certificate) {
    if (this.certificates != null && !this.certificates.isEmpty()) {
      throw new IllegalArgumentException("Can not assign both 'certificate' and 'certificates'");
    }
    this.certificate = certificate;
  }

  /**
   * Assigns the list of resources holding the certificate chain that part of the credential (optional since the
   * certificate may be part of a keystore). If used, the entity certificate must be the first element.
   *
   * @param certificates a list of certificate resources
   */
  public void setCertificates(final List<Resource> certificates) {
    if (this.certificate != null) {
      throw new IllegalArgumentException("Can not assign both 'certificate' and 'certificates'");
    }
    this.certificates = certificates;
  }

  /**
   * Assigns the resource holding the private key part of the credential (optional since the key may be part of a
   * keystore).
   *
   * @param privateKey private key resource
   */
  public void setPrivateKey(final Resource privateKey) {
    this.privateKey = privateKey;
  }

  /**
   * Assigns the resource to the keystore containing the credential.
   *
   * @param resource the keystore resource
   */
  public void setResource(final Resource resource) {
    this.resource = resource;
  }

  /**
   * Assigns the keystore password.
   *
   * @param password keystore password
   */
  public void setPassword(final char[] password) {
    this.password = Optional.ofNullable(password).map(p -> Arrays.copyOf(p, p.length)).orElse(null);
  }

  /**
   * Assigns the type of keystore.
   *
   * @param type the keystore type
   */
  public void setType(final String type) {
    this.type = type;
  }

  /**
   * Assigns the name of the security provider to use when creating the KeyStore instance.
   *
   * @param provider security provider name
   */
  public void setProvider(final String provider) {
    this.provider = provider;
  }

  /**
   * Assigns the PKCS#11 configuration file to use.
   *
   * @param pkcs11Configuration PKCS#11 configuration file (full path)
   */
  public void setPkcs11Configuration(final String pkcs11Configuration) {
    this.pkcs11Configuration = pkcs11Configuration;
  }

  /**
   * Assigns the keystore alias to the entry holding the key pair.
   *
   * @param alias keystore alias
   */
  public void setAlias(final String alias) {
    this.alias = alias;
  }

  /**
   * Assigns the password to unlock the private key from the keystore.
   *
   * @param keyPassword the key password
   */
  public void setKeyPassword(final char[] keyPassword) {
    this.keyPassword = Optional.ofNullable(keyPassword).map(p -> Arrays.copyOf(p, p.length)).orElse(null);
  }

  /**
   * Assigns the PIN. The same as keyPassword (used mainly for PKCS#11 credentials).
   *
   * @param pin the PIN
   */
  public void setPin(final char[] pin) {
    this.setKeyPassword(pin);
  }

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() throws Exception {
    if ((this.certificate != null || (this.certificates != null && !this.certificates.isEmpty()))
        && this.privateKey != null) {
      log.debug("A BasicCredential will be created");
    }
    else if (StringUtils.hasText(this.pkcs11Configuration) && StringUtils.hasText(this.alias)
        && this.keyPassword != null
        && (!StringUtils.hasText(this.type) || "PKCS11".equalsIgnoreCase(this.type))) {
      log.debug("A Pkcs11Credential will be created");
    }
    else if (this.resource != null && this.password != null && this.alias != null) {
      log.debug("A KeyStoreCredential will be created");
    }
    else {
      throw new IllegalArgumentException("Missing credential configuration - cannot create");
    }
    super.afterPropertiesSet();
  }

  /** {@inheritDoc} */
  @Override
  public void destroy() throws Exception {
    super.destroy();
    if (this.password != null) {
      Arrays.fill(this.password, (char) 0);
    }
    if (this.keyPassword != null) {
      Arrays.fill(this.keyPassword, (char) 0);
    }
  }

}
