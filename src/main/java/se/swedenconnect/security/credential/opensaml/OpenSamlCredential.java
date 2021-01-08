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
import java.util.Collection;

import org.opensaml.security.x509.BasicX509Credential;

import net.shibboleth.utilities.java.support.collection.LazySet;
import net.shibboleth.utilities.java.support.logic.Constraint;
import se.swedenconnect.security.credential.Pkcs11Credential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.ReloadablePkiCredential;

/**
 * A credential that implements OpenSAML's {@link org.opensaml.security.x509.X509Credential} interface and wraps a
 * {@link PkiCredential}. This enables us to make use of features such as testing and re-loading (see
 * {@link ReloadablePkiCredential}), but most importantly, it gives use a smooth way of instantiating OpenSAML
 * credentials.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class OpenSamlCredential extends BasicX509Credential {

  /** The underlying credential. */
  private PkiCredential credential = null;

  /** Whether a full certificate chain has been assigned. */
  private boolean chainAssigned = false;

  /**
   * Default constructor.
   */
  public OpenSamlCredential() {
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
  public OpenSamlCredential(final X509Certificate entityCertificate, final PrivateKey privateKey) {
    super(entityCertificate, privateKey);
  }

  /**
   * Constructor setting up the OpenSAML credential by assigning a {@link PkiCredential} instance. This type of setting
   * up the {@code OpenSamlCredential} is recommended since it gives the benefits of monitoring (and reloading)
   * credentials as well as a simple way to use hardware based keys (e.g. {@link Pkcs11Credential}).
   * 
   * @param credential
   *          the credential to wrap in a OpenSAML credential
   */
  public OpenSamlCredential(final PkiCredential credential) {
    super(null);
    this.credential = Constraint.isNotNull(credential, "Credential cannot be null");
  }

  /** {@inheritDoc} */
  @Override
  public PublicKey getPublicKey() {
    return this.credential != null ? this.credential.getPublicKey() : super.getPublicKey();
  }

  /** {@inheritDoc} */
  @Override
  public PrivateKey getPrivateKey() {
    return this.credential != null ? this.credential.getPrivateKey() : super.getPrivateKey();
  }

  /** {@inheritDoc} */
  @Override
  public void setPrivateKey(final PrivateKey privateKey) {
    Constraint.isNull(this.credential, "Private key may not be installed when object is created using a KeyPairCredential");
    super.setPrivateKey(privateKey);
  }

  /** {@inheritDoc} */
  @Override
  public X509Certificate getEntityCertificate() {
    return this.credential != null ? this.credential.getCertificate() : super.getEntityCertificate();
  }

  /** {@inheritDoc} */
  @Override
  public void setEntityCertificate(final X509Certificate entityCertificate) {
    Constraint.isNull(this.credential, "Entity certificate may not be installed when object is created using a KeyPairCredential");
    if (entityCertificate != null) {
      super.setEntityCertificate(entityCertificate);
    }
  }

  /** {@inheritDoc} */
  @Override
  public Collection<X509Certificate> getEntityCertificateChain() {
    if (this.chainAssigned) {
      return super.getEntityCertificateChain();
    }
    else {
      final LazySet<X509Certificate> constructedChain = new LazySet<>();
      constructedChain.add(this.getEntityCertificate());
      return constructedChain;
    }
  }

  /** {@inheritDoc} */
  @Override
  public void setEntityCertificateChain(final Collection<X509Certificate> certificateChain) {
    super.setEntityCertificateChain(certificateChain);
    this.chainAssigned = true;
  }

  /**
   * Assigns a {@link PkiCredential} instance. This type of setting up the {@code OpenSamlCredential} is recommended
   * since it gives the benefits of monitoring (and reloading) credentials as well as a simple way to use hardware based
   * keys.
   * 
   * @param credential
   *          the credential to wrap in a OpenSAML credential
   */
  public void setCredential(final PkiCredential credential) {
    Constraint.isNull(super.getEntityCertificate(), "Credential can not be assigned since certificate has already been assigned");
    Constraint.isNull(super.getPrivateKey(), "Credential can not be assigned since private key has already been assigned");
    this.credential = Constraint.isNotNull(credential, "Credential cannot be null");
  }

}
