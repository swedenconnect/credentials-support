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
package se.swedenconnect.security.pkcs11.configuration;

import java.security.Provider;

/**
 * Interface representing a PKCS#11 configuration.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface Pkcs11Configuration {

  /**
   * Gets the configuration data for this configuration. The data returned is supplied in the
   * {@link Provider#configure(String)} call that is made to configure the PKCS#11 security provider.
   * <p>
   * The returned string represents either a file name to an PKCS#11 configuration file or PKCS#11 configuration
   * commands (in that case the string must be prefixed with {@code --}.
   * </p>
   * 
   * @return configuration data for a PKCS#11 provider
   * @throws InvalidPkcs11ConfigurationException
   *           if the configuration is not valid
   */
  String getConfigurationData() throws InvalidPkcs11ConfigurationException;
  
  /**
   * Returns the path to the PKCS#11 library on the host to use for the provider.
   * 
   * @return path to PKCS#11 library
   */
  String getLibrary();

  /**
   * Returns the name of the HSM slot.
   * 
   * @return the name of the HSM slot
   */
  String getName();

  /**
   * Returns the slot number/id to use.
   * <p>
   * If {@code null} is returned, the device will use the slot entry identified by the active
   * {@link #getSlotListIndex()}.
   * </p>
   * 
   * @return slot number/id, or null
   */
  String getSlot();

  /**
   * Returns the slot list index to use.
   * <p>
   * If no slot list index is assigned ({@code null} is returned), the following logic applies:
   * </p>
   * <ul>
   * <li>If {@code slot} ({@link #getSlot()}) is {@code null}, the default slot list index 0 will be used.</li>
   * <li>If {@code slot} ({@link #getSlot()}) is non-null, the slot identified by this slot number will be used.</li>
   * </ul>
   * 
   * @return the slot list index, or null
   */
  Integer getSlotListIndex();

}
