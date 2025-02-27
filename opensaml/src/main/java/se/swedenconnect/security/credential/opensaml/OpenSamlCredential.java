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
package se.swedenconnect.security.credential.opensaml;

import jakarta.annotation.Nonnull;
import org.opensaml.security.x509.BasicX509Credential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.ReloadablePkiCredential;
import se.swedenconnect.security.credential.pkcs11.Pkcs11Credential;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Objects;
import java.util.Optional;

/**
 * A credential that implements OpenSAML's {@link org.opensaml.security.x509.X509Credential} interface and wraps a
 * {@link PkiCredential}. This enables us to make use of features such as testing and re-loading (see
 * {@link ReloadablePkiCredential}), but most importantly, it gives use a smooth way of instantiating OpenSAML
 * credentials.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
public class OpenSamlCredential extends BasicX509Credential {

  /** The underlying credential. */
  private PkiCredential credential = null;

  /**
   * Constructor setting up the credential by explicitly assigning the certificate and private key.
   *
   * @param entityCertificate the certificate
   * @param privateKey the private key
   */
  public OpenSamlCredential(@Nonnull final X509Certificate entityCertificate, @Nonnull final PrivateKey privateKey) {
    super(entityCertificate, privateKey);
  }

  /**
   * Constructor setting up the OpenSAML credential by assigning a {@link PkiCredential} instance. This type of setting
   * up the {@code OpenSamlCredential} is recommended since it gives the benefits of monitoring (and reloading)
   * credentials as well as a simple way to use hardware based keys (e.g. {@link Pkcs11Credential}).
   *
   * @param credential the credential to wrap in a OpenSAML credential
   */
  public OpenSamlCredential(@Nonnull final PkiCredential credential) {
    super(Objects.requireNonNull(credential, "credential must not be null").getCertificate(),
        credential.getPrivateKey());
    this.credential = credential;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public PublicKey getPublicKey() {
    return Optional.ofNullable(this.credential)
        .map(PkiCredential::getPublicKey)
        .orElseGet(super::getPublicKey);
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public PrivateKey getPrivateKey() {
    return Optional.ofNullable(this.credential)
        .map(PkiCredential::getPrivateKey)
        .orElseGet(super::getPrivateKey);
  }

  /** {@inheritDoc} */
  @Override
  public void setPrivateKey(@Nonnull final PrivateKey privateKey) {
    if (this.credential != null) {
      throw new IllegalArgumentException(
          "Private key may not be installed when object is created using a PkiCredential");
    }
    super.setPrivateKey(privateKey);
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public X509Certificate getEntityCertificate() {
    return Optional.ofNullable(this.credential)
        .map(PkiCredential::getCertificate)
        .orElseGet(super::getEntityCertificate);
  }

  /** {@inheritDoc} */
  @Override
  public void setEntityCertificate(@Nonnull final X509Certificate entityCertificate) {
    if (this.credential != null) {
      throw new IllegalArgumentException(
          "Entity certificate may not be installed when object is created using a PkiCredential");
    }
    if (entityCertificate != null) {
      super.setEntityCertificate(entityCertificate);
    }
  }

  /** {@inheritDoc} */
  @Nonnull
  @Override
  public Collection<X509Certificate> getEntityCertificateChain() {
    if (this.credential != null) {
      return this.credential.getCertificateChain();
    }
    else {
      return super.getEntityCertificateChain();
    }
  }

  /** {@inheritDoc} */
  @Override
  public void setEntityCertificateChain(@Nonnull final Collection<X509Certificate> certificateChain) {
    if (this.credential != null) {
      throw new IllegalArgumentException(
          "Entity certificate chain may not be installed when object is created using a PkiCredential");
    }
    super.setEntityCertificateChain(certificateChain);
  }

  /**
   * Predicate that tells whether this credential resides in a hardware module.
   *
   * @return {@code true} if the credential resides in a hardware module and {@code false} otherwise
   */
  public boolean isHardwareCredential() {
    return this.credential != null && this.credential.isHardwareCredential();
  }

}
