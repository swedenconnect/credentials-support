/*
 * Copyright 2020 Sweden Connect
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
package se.swedenconnect.security.credential.opensaml;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import javax.annotation.PostConstruct;

import org.opensaml.security.x509.BasicX509Credential;

import net.shibboleth.utilities.java.support.logic.Constraint;
import se.swedenconnect.security.credential.KeyPairCredential;
import se.swedenconnect.security.credential.pkcs11.Pkcs11Credential;

/**
 * A credential that implements OpenSAML's {@code org.opensaml.security.x509.X509Credential} interface.
 * <p>
 * Yes. The name of this class is {@code X509Credential}. The same as the interface that is implements (via the
 * extension of {@link BasicX509Credential}). We really didn't want to use any "Wrapper" och "Ext", so ... But this is a
 * class and {@link org.opensaml.security.x509.X509Credential} is an interface so it should work fine.
 * </p>
 * <p>
 * A note about reloading of re-loading of credentials (as defined in the {@link KeyPairCredential} interface): This
 * will only work if the {@code X509Credential} is instantiated using the {@link #X509Credential(KeyPairCredential)}
 * constructor <b>and</b> the supplied {@link KeyPairCredential}.
 * </p>
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class X509Credential extends BasicX509Credential implements KeyPairCredential {

  /** The underlying credential. */
  private KeyPairCredential credential = null;

  /** Credential name. */
  private String name;

  /**
   * Default constructor.
   */
  public X509Credential() {
    super(null);
  }

  /**
   * Constructor setting up the credential by explicitly assigning the certificate and private key.
   * 
   * @param entityCertificate
   *          the certificate
   * @param privateKey
   *          the private key
   */
  public X509Credential(final X509Certificate entityCertificate, final PrivateKey privateKey) {
    super(entityCertificate, privateKey);
  }

  /**
   * Constructor setting up the OpenSAML credential by assigning a {@link KeyPairCredential} instance. This type of
   * setting up the {@code X509Credential} is recommended since it gives the benefits of monitoring (and reloading)
   * credentials as well as a simple way to use hardware based keys (via {@link Pkcs11Credential}).
   * 
   * @param credential
   *          the credential to wrap in a OpenSAML credential
   */
  public X509Credential(final KeyPairCredential credential) {
    super(null);
    this.credential = Constraint.isNotNull(credential, "Credential cannot be null");
    this.name = this.credential.getName();
    super.setEntityCertificate(credential.getCertificate());
  }

  /**
   * Validates that all required properties have been assigned. This method is automatically invoked if the class is
   * used within a bean framework that supports the {@code PostConstruct} annotation (such as Spring).
   * 
   * @throws Exception
   *           if certificate or private key has not been assigned
   */
  @PostConstruct
  public void afterPropertiesSet() throws Exception {
    if (this.credential == null) {
      if (this.getCertificate() == null) {
        throw new IllegalArgumentException("Property 'certificate'/'entityCertificate' must be assigned");
      }
      if (this.getPrivateKey() == null) {
        throw new IllegalArgumentException("Property 'privateKey' must be assigned");
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public PublicKey getPublicKey() {
    if (this.credential != null) {
      return this.credential.getPublicKey();
    }
    else {
      final X509Certificate cert = this.getEntityCertificate();
      return cert != null ? cert.getPublicKey() : null;
    }
  }

  /** {@inheritDoc} */
  @Override
  public PrivateKey getPrivateKey() {
    if (this.credential != null) {
      return this.credential.getPrivateKey();
    }
    return super.getPrivateKey();
  }

  /** {@inheritDoc} */
  @Override
  public void setPrivateKey(final PrivateKey privateKey) {
    if (this.credential != null) {
      throw new UnsupportedOperationException(
        "Private key may not be installed when object is created using a KeyPairCredential");
    }
    super.setPrivateKey(privateKey);
  }

  /** {@inheritDoc} */
  @Override
  public void setEntityCertificate(final X509Certificate entityCertificate) {
    if (this.credential != null) {
      throw new UnsupportedOperationException(
        "Entity certificate may not be installed when object is created using a KeyPairCredential");
    }
    else if (entityCertificate != null) {
      super.setEntityCertificate(entityCertificate);
    }
  }

  /** {@inheritDoc} */
  @Override
  public X509Certificate getCertificate() {
    return this.getEntityCertificate();
  }

  /**
   * Assigns the end entity certificate.
   * 
   * @param certificate
   *          the certificate to assign
   */
  public void setCertificate(final X509Certificate certificate) {
    this.setEntityCertificate(certificate);
  }

  /** {@inheritDoc} */
  @Override
  public String getName() {
    return this.name;
  }

  /**
   * Assigns the credential name.
   * 
   * @param name
   *          the credential name
   */
  public void setName(final String name) {
    this.name = name;
  }

  /** {@inheritDoc} */
  @Override
  public void reload() throws SecurityException {
    if (this.credential != null) {
      this.credential.reload();
    }
  }

}
