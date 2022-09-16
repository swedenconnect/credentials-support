/**
 * Support for credential containers.
 *
 * <p>
 *   Credential containers are mainly provided to support the use of HSM slots for generating and managing
 *   public and private key pairs. But even though HSM slots are the primary use-case, this implementation also
 *   fully supports credential containers where the keys are stored on disk or in memory using key stores
 * </p>
 */
package se.swedenconnect.security.credential.container;