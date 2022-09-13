package se.swedenconnect.security.credential.container;

import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.container.exceptions.PkiCredentialContainerException;
import se.swedenconnect.security.credential.container.keytype.KeyGenType;

import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.util.List;

/**
 * This interface defined the function of a multi credential container with keys that are contained and managed
 * inside the container for its entire lifetime.
 *
 * <p>
 *   The primary use-case for this credential container is to be used with a HSM for generating ephemeral key credentials
 *   that are generated inside the HSM and used for a short period of time and then deleted without ever leaving
 *   the HSM. A typical use-case for this scenario is the generation usd and destruction of signing keys in a signing
 *   service where the signing key is used only once and then destroyed in order to guarantee that the key can never
 *   be used in any other process for any other purpose.
 * </p>
 *
 * <p>
 *   While the primary use-case for this multi credential container is for use with HSM, it may also be implemented
 *   using a software based key store for implementations with less demands for security or for the purpose of testing
 *   and prototyping
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface PkiCredentialContainer {

  /**
   * Generate key pair and self issued certificate for a new credential in the container
   *
   * @param keyTypeId the id of the type of key to generate as provided by {@link KeyGenType}
   * @return the alias for the generated key
   * @throws KeyException on errors generating the key
   * @throws NoSuchAlgorithmException if the requested algorithm or key type is not supported
   * @throws CertificateException on errors creating a certificate for the generated key
   */
  String generateCredential(String keyTypeId) throws KeyException, NoSuchAlgorithmException, CertificateException;

  /**
   * Get the credential for a specific alias from the credential container
   *
   * @param alias the alias of the credential to get
   * @return credential for the specified alias
   * @throws PkiCredentialContainerException error obtaining the requested credential
   */
  PkiCredential getCredential(String alias) throws PkiCredentialContainerException;

  /**
   * Delete the credential specified by alias
   *
   * @param alias the alias of the credential to delete
   * @throws PkiCredentialContainerException error deleting the credential
   */
  void deleteCredential(String alias) throws PkiCredentialContainerException;

  /**
   * Get the expiry time of the credential specified by alias
   *
   * @param alias alias of the requested credential
   * @return expiry time for the specified credential or null if the credential never expires
   * @throws PkiCredentialContainerException error obtaining the expiry time
   */
  Instant getExpiryTime(String alias) throws PkiCredentialContainerException;

  /**
   * Get all available credential aliases from the multi credential key store
   *
   * @return list of credential aliases
   * @throws PkiCredentialContainerException error listing available credentials
   */
  List<String> getAvailableCredentials() throws PkiCredentialContainerException;

  /**
   * Traverse through all credentials in the multi credential key store
   *
   * @throws PkiCredentialContainerException error performing cleanup
   */
  void cleanup() throws PkiCredentialContainerException;
}
