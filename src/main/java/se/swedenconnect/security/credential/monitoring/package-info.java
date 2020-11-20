/**
 * Some types of credentials may need to be monitored to ensure that they are still in function. Especially those that
 * resides on hardware devices such as HSM:s. This package contains support for setting up monitoring threads that tests
 * (and reloads) credentials.
 */
package se.swedenconnect.security.credential.monitoring;