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
package se.swedenconnect.security.credential.pkcs11.configuration;

import java.security.PrivateKey;
import java.security.Provider;

import se.swedenconnect.security.credential.KeyPairCredential;
import se.swedenconnect.security.credential.pkcs11.Pkcs11ObjectProvider;

/**
 * Interface representing a PKCS#11 configuration.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface Pkcs11Configuration {

  /**
   * Gets the Java security {@link Provider} to use when setting up a PKCS#11 credential.
   * 
   * @return a Provider instance
   * @throws Pkcs11ConfigurationException
   *           if the configuration is incorrect
   */
  Provider getProvider() throws Pkcs11ConfigurationException;

  /**
   * Gets the getter function object that should be used to obtain a private key from the PKCS#11 device.
   * <p>
   * How the private key is obtained from the device is dependent on the security provider used.
   * </p>
   * <p>
   * Note: If both the private key <b>and</b> the certificate should be obtained from the device, use
   * {@link #getKeyPairProvider()} instead.
   * </p>
   * 
   * @return a Pkcs11ObjectProvider instance
   */
  Pkcs11ObjectProvider<PrivateKey> getPrivateKeyProvider();

  /**
   * Gets the getter function object that should be used to obtain the private key and certificate from the PKCS#11
   * device.
   * <p>
   * How the objects are obtained from the device is dependent on the security provider used.
   * </p>
   * <p>
   * For some HSM-deployments the certificate is not kept on the device, only the private key. The
   * {@link KeyPairCredential} object returned from the provider will then return {@code null} for a
   * {@link KeyPairCredential#getCertificate()} call.
   * </p>
   * 
   * @return a Pkcs11ObjectProvider instance
   */
  Pkcs11ObjectProvider<KeyPairCredential> getKeyPairProvider();

  /**
   * Gets the complete path to the configuration file.
   * 
   * @return the PKCS#11 configuration file
   */
  String getConfigurationFile();

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
