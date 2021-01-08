/*
 * Copyright 2020-2021 Sweden Connect
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

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.springframework.core.io.Resource;

import se.swedenconnect.security.credential.factory.X509CertificateFactoryBean;

/**
 * Abstract base class for classes implementing the {@link PkiCredential} interface.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public abstract class AbstractPkiCredential implements PkiCredential {

  /** The private key. */
  private PrivateKey privateKey;

  /** The certificate. */
  private X509Certificate certificate;

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
    return this.certificate != null ? this.certificate.getPublicKey() : this.publicKey;
  }

  /**
   * Assigns the public key of the key pair.
   * 
   * @param publicKey
   *          the public key.
   */
  public void setPublicKey(final PublicKey publicKey) {
    if (this.certificate != null) {
      throw new IllegalArgumentException("Cannot assign public key - certificate has already been assigned");
    }
    this.publicKey = publicKey;
  }

  /** {@inheritDoc} */
  @Override
  public X509Certificate getCertificate() {
    return this.certificate;
  }

  /**
   * Assigns the certificate.
   * 
   * @param certificate
   *          the certificate
   */
  public void setCertificate(final X509Certificate certificate) {
    if (this.publicKey != null) {
      throw new IllegalArgumentException("Cannot assign certificate - public key has already been assigned");
    }
    this.certificate = certificate;
  }

  /**
   * Assigns the certificate by assigning a resource pointing to a DER- och PEM-encoded certificate.
   * 
   * @param certificateResource
   *          the certificate resource
   * @throws CertificateException
   *           if the supplied resource cannot be decoded into a {@link X509Certificate} instance
   */
  public void setCertificate(final Resource certificateResource) throws CertificateException {
    if (this.publicKey != null) {
      throw new IllegalArgumentException("Cannot assign certificate - public key has already been assigned");
    }
    try {
      X509CertificateFactoryBean factory = new X509CertificateFactoryBean(certificateResource);
      factory.afterPropertiesSet();
      this.certificate = factory.getObject();
    }
    catch (Exception e) {
      if (e instanceof CertificateException) {
        throw (CertificateException) e;
      }
      else {
        throw new IllegalArgumentException("Failed to read certificate resource", e);
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public PrivateKey getPrivateKey() {
    return this.privateKey;
  }

  /**
   * Assigns the private key.
   * 
   * @param privateKey
   *          the private key
   */
  public void setPrivateKey(final PrivateKey privateKey) {
    this.privateKey = privateKey;
  }

  /**
   * Gets the name of the credential. If no name has been explicitly assigned, {@link #getDefaultName()} is used.
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
   * @param name
   *          the name
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
      throw new IllegalArgumentException("Either 'certificate' or 'publicKey' must be assigned");
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
