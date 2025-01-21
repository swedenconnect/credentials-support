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
package se.swedenconnect.security.credential.config;

import java.util.Optional;

/**
 * Configuration interface for creating a Java {@link java.security.KeyStore KeyStore}.
 *
 * @author Martin Lindström
 */
public interface StoreConfiguration {

  /**
   * Location of the resource containing the store content.
   *
   * @return the location of the resource containing the store content
   */
  Optional<String> location();

  /**
   * Password used to access the store.
   *
   * @return the password used to access the store
   */
  String password();

  /**
   * Type of the store to create, e.g., JKS, PKCS12 or PKCS11.
   *
   * @return the type of the store to create
   */
  Optional<String> type();

  /**
   * Security provider for the store.
   *
   * @return the name of the security provider for the store
   */
  Optional<String> provider();

  /**
   * If the {@code type} is "PKCS11" and a provider that is not statically configured for PKCS#11, additional PKCS#11
   * configuration needs to be supplied.
   * <p>
   * Note: The security provider used must support PKCS#11 via the {@link java.security.KeyStoreSpi KeyStoreSpi}
   * interface. The "SunPKCS11" is such a provider.
   * </p>
   *
   * @return additional PKCS#11 configuration
   */
  Optional<Pkcs11Configuration> pkcs11();

  /**
   * Additional configuration of PKCS11 keystores.
   */
  interface Pkcs11Configuration {

    /**
     * The complete path of the PKCS#11 configuration file with which the PKCS#11 device is configured.
     *
     * @return complete path of the PKCS#11 configuration file with which the PKCS#11 device is configured
     */
    Optional<String> configurationFile();

    /**
     * As an alternative to providing the PKCS#11 configuration file, each PKCS#11 setting can be provided separately.
     * This property holds these detailed settings.
     *
     * @return custom PKCS#11 settings
     */
    Optional<Pkcs11Settings> settings();

    /**
     * Custom PKCS#11 settings.
     */
    interface Pkcs11Settings {

      /**
       * The PKCS#11 library path.
       *
       * @return the PKCS#11 library path
       */
      String library();

      /**
       * The name of the PKCS#11 slot.
       *
       * @return the name of the PKCS#11 slot
       */
      String name();

      /**
       * The slot number/id to use.
       *
       * @return slot number/id to use
       */
      Optional<String> slot();

      /**
       * The slot index to use.
       *
       * @return the slot index to use
       */
      Optional<Integer> slotListIndex();
    }

  }

}
