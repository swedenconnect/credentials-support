/*
 * Copyright 2020-2024 Sweden Connect
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
package se.swedenconnect.security.credential.config;

import java.util.Optional;

/**
 * Configuration interface for creating a {@link se.swedenconnect.security.credential.PkiCredential PkiCredential}
 * backed by a Java {@link java.security.KeyStore KeyStore}.
 *
 * @author Martin Lindström
 */
public interface StoreCredentialConfiguration extends BaseCredentialConfiguration {

  /**
   * Configuration for the {@link java.security.KeyStore KeyStore} holding the key pair entry.
   *
   * @return key store configuration
   */
  Optional<StoreConfiguration> store();

  /**
   * As an alternative to giving the key store configuration, a reference to a key store configuration may be given.
   * This feature may be used when one key store holds several keys.
   *
   * @return a key store reference
   */
  Optional<String> storeReference();

  /**
   * Whether the credential should be prepared for monitoring. If set, a test function and a
   * {@link se.swedenconnect.security.credential.KeyStoreReloader KeyStoreReloader} will be assigned.
   * <p>
   * If not present, the default should be {@code true} for PKCS#11 stores, and {@code false} otherwise
   * </p>
   *
   * @return whether the credential should be prepared for monitoring
   */
  Optional<Boolean> monitor();

  /**
   * Configuration for the key pair entry of the store.
   *
   * @return the key entry configuration
   */
  KeyConfiguration key();

  /**
   * Configuration interface for a key pair entry.
   */
  interface KeyConfiguration {

    /**
     * The alias that identifies the key pair in the key store.
     *
     * @return the key store alias
     */
    String alias();

    /**
     * The password to unlock the key entry identified by the given alias. If not given, the store password will be used
     * (in these cases, using a store reference will not function).
     *
     * @return the password to unlock the key entry
     */
    Optional<String> keyPassword();

    /**
     * For some credentials where an underlying {@link java.security.KeyStore KeyStore} is being used, an external
     * certificate should be used. The most typical example would be a PKCS#11 key store where the certificate of the
     * key pair resides outside the HSM device. This setting holds the location or content of the certificate or
     * certificate chain in PEM format.
     *
     * @return location or content of the certificate or certificate chain in PEM format for externally configured
     *     certificates
     */
    Optional<String> certificates();
  }

}
