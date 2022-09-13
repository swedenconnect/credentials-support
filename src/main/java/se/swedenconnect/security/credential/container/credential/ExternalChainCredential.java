/*
 * Copyright (c) 2021-2022. Agency for Digital Government (DIGG)
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
package se.swedenconnect.security.credential.container.credential;

import se.swedenconnect.security.credential.PkiCredential;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Implements a {@link PkiCredential} that uses an inner base credential to store the private key only and provides the
 * ability to freely set and change the certificate chain associated with that private key.
 *
 * <p>
 * This implementation of PkiCredential is important when setting up a CA or OCSP where we may have to set the chain
 * from another source than the key store or the HSM holding the private key.
 * </p>
 *
 * <p>
 * This implementation is not necessarily used as a bean that is wired into the system as a preconfigured credential. On
 * the contrary, this credential is normally used when the credential is setup in steps before it is ready to be used.
 * Example:
 * </p>
 *
 * <ul>
 * <li>The credential is first initiated with the key and certificate from a hsm slot</li>
 * <li>Then the credential is used to issue a new self-issued certificate suitable for the service</li>
 * <li>The self issued certificate is replacing the first chain of this credential</li>
 * <li>The self issued certificate is sent to another CA to be certified</li>
 * <li>The credential is updated with the resulting chain</li>
 * </ul>
 *
 * <p>
 * This is the main reason why this credential both sets the chain at construction and has setters for the same data
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ExternalChainCredential implements PkiCredential {

  private List<X509Certificate> certificateChain;
  private final PkiCredential baseCredential;

  /**
   * Constructor providing an external chain credential from a base credential only.
   *
   * @param baseCredential a base credential holding a private and a public key
   */
  public ExternalChainCredential(final PkiCredential baseCredential) {
    this(null, baseCredential);
  }

  /**
   * Constructor for the external chain credential.
   *
   * @param certificateChain an optional external certificate chain to associate with this credential private key
   * @param baseCredential the base credential holding a public and private key
   */
  public ExternalChainCredential(final List<X509Certificate> certificateChain, final PkiCredential baseCredential) {
    // As prio 1 we set any externally specified chain
    this.certificateChain = certificateChain == null ? new ArrayList<>() : certificateChain;
    this.baseCredential = baseCredential;
    if (this.certificateChain.isEmpty()) {
      // If not certificate chain was set. Attempt to import any chain from the base credential
      this.certificateChain = baseCredential.getCertificateChain();
    }
    // This credential must be ready to use ofter construction. We therefore make the basic checks
    // already at this point
    try {
      this.afterPropertiesSet();
    }
    catch (final Exception e) {
      throw new IllegalArgumentException(e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public PublicKey getPublicKey() {
    return this.certificateChain.get(0).getPublicKey();
  }

  /** {@inheritDoc} */
  @Override
  public X509Certificate getCertificate() {
    return this.certificateChain.get(0);
  }

  /** {@inheritDoc} */
  @Override
  public void setCertificate(final X509Certificate x509Certificate) {
    Objects.requireNonNull(x509Certificate, "Certificate must not be null");
    this.certificateChain = List.of(x509Certificate);
  }

  /** {@inheritDoc} */
  @Override
  public List<X509Certificate> getCertificateChain() {
    return this.certificateChain;
  }

  /** {@inheritDoc} */
  @Override
  public void setCertificateChain(final List<X509Certificate> certificateChain) {
    Objects.requireNonNull(certificateChain, "Certificate chain must not be null");
    if (certificateChain.isEmpty()) {
      throw new IllegalArgumentException("Certificate chain must not be empty");
    }
    this.certificateChain = certificateChain;
  }

  /** {@inheritDoc} */
  @Override
  public PrivateKey getPrivateKey() {
    return this.baseCredential.getPrivateKey();
  }

  /** {@inheritDoc} */
  @Override
  public String getName() {
    final X509Certificate cert = this.getCertificate();
    if (cert != null) {
      return cert.getSubjectX500Principal().getName();
    }
    else {
      final PublicKey key = this.getPublicKey();
      return key != null ? String.format("%s-%s", key.getAlgorithm(), UUID.randomUUID())
          : "ExtendedCredential-" + UUID.randomUUID().toString();
    }
  }

  /** {@inheritDoc} */
  @Override
  public void destroy() throws Exception {
  }

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() throws Exception {
    if (this.getPublicKey() == null) {
      throw new IllegalArgumentException("Either 'certificate'/'certificates' or 'publicKey' must be assigned");
    }
    else if (this.getPrivateKey() == null) {
      throw new IllegalArgumentException("Property 'privateKey' must be assigned");
    }
  }
}
