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
package se.swedenconnect.security.credential;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import org.cryptacular.util.KeyPairUtil;
import org.springframework.core.io.Resource;

import se.swedenconnect.security.credential.utils.PrivateKeyUtils;
import se.swedenconnect.security.credential.utils.X509Utils;

/**
 * Abstract base class for classes implementing the {@link PkiCredential} interface.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public abstract class AbstractPkiCredential implements PkiCredential {

  /** The private key. */
  private PrivateKey privateKey;

  /** The certificates. */
  private List<X509Certificate> certificates;

  /** The public key. */
  private PublicKey publicKey;

  /** The credential name. */
  private String name;

  /**
   * Default constructor.
   */
  public AbstractPkiCredential() {
  }

  /** {@inheritDoc} */
  @Override
  public PublicKey getPublicKey() {
    return Optional.ofNullable(this.getCertificate())
        .map(X509Certificate::getPublicKey)
        .orElseGet(() -> this.publicKey);
  }

  /**
   * Assigns the public key of the key pair.
   *
   * @param publicKey the public key.
   */
  public void setPublicKey(final PublicKey publicKey) {
    if (this.certificates != null && !this.certificates.isEmpty()) {
      throw new IllegalArgumentException("Cannot assign public key - certificate(s) has already been assigned");
    }
    this.publicKey = publicKey;
  }

  /** {@inheritDoc} */
  @Override
  public X509Certificate getCertificate() {
    return Optional.ofNullable(this.certificates)
        .filter(c -> !c.isEmpty())
        .map(c -> c.get(0))
        .orElse(null);
  }

  /** {@inheritDoc} */
  @Override
  public void setCertificate(final X509Certificate certificate) {
    if (this.publicKey != null && certificate != null) {
      if (!Arrays.equals(this.publicKey.getEncoded(), certificate.getPublicKey().getEncoded())) {
        throw new IllegalArgumentException(
            "Cannot assign certificate - it does not match already installed public key");
      }
      this.publicKey = null;
    }
    this.certificates = certificate != null ? Collections.singletonList(certificate) : null;
  }

  /**
   * Assigns the certificate by assigning a resource pointing to a DER- och PEM-encoded certificate.
   *
   * @param certificateResource the certificate resource
   * @throws CertificateException if the supplied resource cannot be decoded into a X509Certificate instance
   */
  public void setCertificate(final Resource certificateResource) throws CertificateException {
    if (certificateResource != null) {
      this.setCertificate(X509Utils.decodeCertificate(certificateResource));
    }
    else {
      this.certificates = null;
    }
  }

  /** {@inheritDoc} */
  @Override
  public List<X509Certificate> getCertificateChain() {
    return Optional.ofNullable(this.certificates)
        .orElseGet(() -> Collections.emptyList());
  }

  /** {@inheritDoc} */
  @Override
  public void setCertificateChain(final List<X509Certificate> certificates) {
    if (certificates != null && certificates.isEmpty()) {
      throw new IllegalArgumentException("Supplied certificate chain must contain at least one certificate");
    }

    if (this.publicKey != null && certificates != null) {
      if (!Arrays.equals(this.publicKey.getEncoded(), certificates.get(0).getPublicKey().getEncoded())) {
        throw new IllegalArgumentException(
            "Cannot assign certificate(s) - entity certificate does not match already installed public key");
      }
      this.publicKey = null;
    }
    this.certificates = certificates != null ? Collections.unmodifiableList(certificates) : null;
  }

  /** {@inheritDoc} */
  @Override
  public PrivateKey getPrivateKey() {
    return this.privateKey;
  }

  /**
   * Assigns the private key.
   *
   * @param privateKey the private key
   */
  public void setPrivateKey(final PrivateKey privateKey) {
    this.privateKey = privateKey;
  }

  /**
   * Assigns a private key resource.
   *
   * @param privateKeyResource a resource holding the key in DER, PEM, or unencrypted PKCS#8 format.
   * @throws KeyException if the key decode fails
   */
  public void setPrivateKey(final Resource privateKeyResource) throws KeyException {
    this.privateKey = PrivateKeyUtils.decodePrivateKey(privateKeyResource);
  }

  /**
   * Assigns a private key resource holding an encrypted private key. The following formats are supported:
   * <ul>
   * <li>DER or PEM encoded PKCS#8 format</li>
   * <li>PEM encoded OpenSSL "traditional" format</li>
   * </ul>
   *
   * @param privateKeyResource a resource holding the key in DER, PEM, or PKCS#8 format.
   * @param password the key password
   * @throws KeyException if the key decode/decrypt fails
   */
  public void setPrivateKey(final Resource privateKeyResource, final char[] password) throws KeyException {
    if (password == null || password.length == 0) {
      this.setPrivateKey(privateKeyResource);
    }
    else {

      try (final InputStream is = privateKeyResource.getInputStream()) {
        this.privateKey = KeyPairUtil.readPrivateKey(is, password);
      }
      catch (final IOException e) {
        throw new KeyException("IO error", e);
      }
    }
  }

  /**
   * Gets the name of the credential. If no name has been explicitly assigned, the default name is used.
   */
  @Override
  public String getName() {
    return this.name != null ? this.name : this.getDefaultName();
  }

  /**
   * If the credential {@code name} property is not explicitly assigned using {@link #setName(String)} a name is
   * calculated based on a credential's properties.
   * <p>
   * Implementations must not assume that the object has been correctly initialized.
   * </p>
   *
   * @return the credential name
   */
  protected abstract String getDefaultName();

  /**
   * Assigns the credential name.
   *
   * @param name the name
   */
  public void setName(final String name) {
    this.name = name;
  }

  /**
   * The default implementation verfies that the public key and the private key is available. Implementations that needs
   * to be initialized (for example by loading the keys) should override this method.
   */
  @Override
  public void afterPropertiesSet() throws Exception {
    if (this.getPublicKey() == null) {
      throw new IllegalArgumentException("Either 'certificate'/'certificates' or 'publicKey' must be assigned");
    }
    if (this.privateKey == null) {
      throw new IllegalArgumentException("Property 'privateKey' must be assigned");
    }
  }

  /**
   * Implementations that need to perform clean-up actions should override this method. The default implementation does
   * nothing.
   */
  @Override
  public void destroy() throws Exception {
  }

}
