/*
 * Copyright 2020-2022 Sweden Connect
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

import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.container.keytype.KeyGenType;

/**
 * This interface defines the function of a multi credential container with keys that are contained and managed inside
 * the container for its entire lifetime.
 *
 * <p>
 * The primary use-case for this credential container is to be used with a HSM for generating ephemeral key credentials
 * that are generated inside the HSM and used for a short period of time and then deleted without ever leaving the HSM.
 * A typical use-case for this scenario is the generation and destruction of signing keys in a signature service where
 * the signing key is used only once and then destroyed in order to guarantee that the key can never be used in any
 * other process for any other purpose.
 * </p>
 * <p>
 * While the primary use-case for this credential container is for use with HSM, it may also be implemented using a
 * software based key store for implementations with less demands for security or for the purpose of testing and
 * prototyping.
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface PkiCredentialContainer {

  /**
   * Generates a key pair and self-issued certificate for a new credential in the container.
   * <p>
   * Note that self-issued certificates may be replaced after a credential has been generated. This is typically done
   * after a CA has issued a certificate for the key pair.
   * </p>
   *
   * @param keyTypeName the id of the type of key to generate as provided by {@link KeyGenType}
   * @return the alias for the generated key
   * @throws KeyException on errors generating the key
   * @throws NoSuchAlgorithmException if the requested algorithm or key type is not supported
   * @throws CertificateException on errors creating a certificate for the generated key
   */
  String generateCredential(final String keyTypeName)
      throws KeyException, NoSuchAlgorithmException, CertificateException;

  /**
   * Gets the credential for a specific alias from the credential container.
   *
   * @param alias the alias of the credential to get
   * @return credential for the specified alias
   * @throws PkiCredentialContainerException for errors obtaining the requested credential
   */
  PkiCredential getCredential(final String alias) throws PkiCredentialContainerException;

  /**
   * Deletes the credential specified by the supplied alias.
   * <p>
   * The "normal" way of deleting a credential is to invoke its {@link PkiCredential#destroy()} method. The {code
   * deleteCredential} method is mainly for internal (and external) container maintenance.
   * </p>
   *
   * @param alias the alias of the credential to delete
   * @throws PkiCredentialContainerException error deleting the credential
   */
  void deleteCredential(final String alias) throws PkiCredentialContainerException;

  /**
   * Gets the expiry time of the credential specified by alias.
   *
   * @param alias alias of the requested credential
   * @return expiry time for the specified credential or null if the credential never expires
   * @throws PkiCredentialContainerException error obtaining the expiry time
   */
  Instant getExpiryTime(final String alias) throws PkiCredentialContainerException;

  /**
   * Gets all available credential aliases from the multi credential key store.
   *
   * @return list of credential aliases
   * @throws PkiCredentialContainerException error listing available credentials
   */
  List<String> listCredentials() throws PkiCredentialContainerException;

  /**
   * Traverses through all credentials in the multi credential key store and delets the expired ones.
   *
   * @throws PkiCredentialContainerException error performing cleanup
   */
  void cleanup() throws PkiCredentialContainerException;

  /**
   * Assigns the duration for the validity of generated credentials.
   *
   * @param keyValidity the validity
   */
  public void setKeyValidity(final Duration keyValidity);

  /**
   * Assigns the key types that this container supports.
   *
   * @param supportedKeyTypes a list of supported key types
   */
  public void setSupportedKeyTypes(final List<String> supportedKeyTypes);
}
