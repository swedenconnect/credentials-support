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
package se.swedenconnect.security.credential.container;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.cryptacular.util.KeyPairUtil;
import se.swedenconnect.security.credential.AbstractReloadablePkiCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.ReloadablePkiCredential;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;

/**
 * A managed {@link PkiCredential} is used when a {@link PkiCredentialContainer} returns credentials. The recipient of a
 * managed credential may invoke {@link #destroy()} to remove the credential from the container, and also update the
 * certifcate of the managed credential.
 *
 * @author Martin Lindström
 */
public class ManagedPkiCredential extends AbstractReloadablePkiCredential {

  /** The instance that we are "managing". */
  private final PkiCredential managedCredential;

  /** Name of the credetial - the same as the managed credential. */
  private final String name;

  /** Certificate(s) added after the creation of the managed credential. */
  private List<X509Certificate> managedCertificates;

  /** Callback to inform the owning container that the credential has been destroyed. */
  private final Consumer<PkiCredential> destroyCallback;

  /** Callback to inform the underlying credential that a certificate chain has been added. */
  private final Consumer<X509Certificate[]> updateCertificateCallback;

  /** Flag used to avoid executing destruction several times. */
  private boolean destroyed;

  /**
   * Constructor setting the credential to be managed and callbacks to be used by the underlying container.
   *
   * @param managedCredential the credential being managed
   * @param destroyCallback a callback that is invoked if the {@link #destroy()} method is called
   * @param updateCertificateCallback optional callback that is invoked if {@link #setCertificate(X509Certificate)}
   *     or {@link #setCertificateChain(List)} is called. This gives the owner of the managed credential the possibility
   *     to update the underlying credential
   */
  public ManagedPkiCredential(
      @Nonnull final PkiCredential managedCredential, @Nonnull final Consumer<PkiCredential> destroyCallback,
      @Nullable final Consumer<X509Certificate[]> updateCertificateCallback) {
    this.managedCredential = Objects.requireNonNull(managedCredential, "managedCredential must not be null");
    this.name = managedCredential.getName();
    this.destroyCallback = Objects.requireNonNull(destroyCallback, "destroyCallback must not be null");
    this.destroyed = false;
    this.updateCertificateCallback = updateCertificateCallback;
  }

  /**
   * Assigns a new certificate for the credential. This certificate must still form a valid key pair given the private
   * key.
   *
   * @param certificate the new certificate
   */
  public void setCertificate(@Nonnull final X509Certificate certificate) {
    this.setCertificateChain(List.of(Objects.requireNonNull(certificate, "certificate must not be null")));
  }

  /**
   * Assigns a new certificate chain for the credential. This first certificate (entity certificate) must still form a
   * valid key pair given the private key.
   *
   * @param certificates the new certificate chain (entity certificate must be placed first)
   */
  public void setCertificateChain(@Nonnull final List<X509Certificate> certificates) {
    if (Objects.requireNonNull(certificates, "certificates must not be null").isEmpty()) {
      throw new IllegalArgumentException("At least one certificate is required");
    }
    this.managedCertificates = Collections.unmodifiableList(certificates);

    if (this.updateCertificateCallback != null) {
      this.updateCertificateCallback.accept(certificates.toArray(new X509Certificate[0]));
    }
  }

  /**
   * If a certificate or certificate chain has been added after the creation of the managed credential, this chain will
   * be returned, otherwise the credential's original chain.
   */
  @Nonnull
  @Override
  public List<X509Certificate> getCertificateChain() {
    return this.managedCertificates != null ? this.managedCertificates : this.managedCredential.getCertificateChain();
  }

  /** {@inheritDoc} */
  @Nonnull
  @Override
  public PublicKey getPublicKey() {
    return Optional.ofNullable(this.getCertificate())
        .map(X509Certificate::getPublicKey)
        .orElseGet(() -> Optional.ofNullable(this.managedCredential.getPublicKey())
            .orElseThrow(() -> new IllegalArgumentException("No public key found")));
  }

  /**
   * Returns the {@link PrivateKey} of the managed credential.
   */
  @Nonnull
  @Override
  public PrivateKey getPrivateKey() {
    return this.managedCredential.getPrivateKey();
  }

  /** {@inheritDoc} */
  @Override
  public boolean isHardwareCredential() {
    return this.managedCredential.isHardwareCredential();
  }

  /** {@inheritDoc} */
  @Nonnull
  @Override
  public String getName() {
    return this.name;
  }

  /**
   * Will
   *
   * @param name the name
   */
  @Override
  public void setName(@Nonnull final String name) {
    throw new IllegalArgumentException("The credential name can not be set");
  }

  // Will never be called
  @Nonnull
  @Override
  protected String getDefaultName() {
    return "";
  }

  /**
   * If not already destroyed, the method will invoke the {@link PkiCredential#destroy()} method on the managed
   * credential, and then invoke the destroy callback to inform the owning container about that the credential should be
   * removed.
   */
  @Override
  public void destroy() {
    if (!this.destroyed) {
      this.destroyed = true;
      this.managedCredential.destroy();
      this.destroyCallback.accept(this.managedCredential);
    }
  }

  /**
   * If the managed credential implements {@link ReloadablePkiCredential}, the {@link ReloadablePkiCredential#reload()}
   * method will be called on the managed credential.
   */
  @Override
  public void reload() throws Exception {
    if (this.managedCredential instanceof final ReloadablePkiCredential reloadableCredential) {
      reloadableCredential.reload();
    }
  }

}
