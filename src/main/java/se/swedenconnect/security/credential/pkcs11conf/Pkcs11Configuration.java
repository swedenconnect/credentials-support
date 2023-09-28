/*
 * Copyright 2020-2023 Sweden Connect
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
package se.swedenconnect.security.credential.pkcs11conf;

import java.security.PrivateKey;
import java.security.Provider;

import se.swedenconnect.security.credential.PkiCredential;

/**
 * Interface for a PKCS#11 configuration.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface Pkcs11Configuration {

  /**
   * Gets the Java security {@link Provider} to use when setting up a PKCS#11 credential.
   *
   * @return a Provider instance
   * @throws Pkcs11ConfigurationException if the configuration is incorrect
   */
  Provider getProvider() throws Pkcs11ConfigurationException;

  /**
   * Gets the getter function object that should be used to obtain a private key from the PKCS#11 device.
   * <p>
   * How the private key is obtained from the device is dependent on the security provider used.
   * </p>
   * <p>
   * Note: If both the private key <b>and</b> the certificate should be obtained from the device, use
   * {@link #getCredentialProvider()} instead.
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
   * In some HSM-deployments the certificate is not kept on the device, only the private key. The {@link PkiCredential}
   * object returned from the provider will then return {@code null} for a {@link PkiCredential#getCertificate()} call.
   * </p>
   *
   * @return a Pkcs11ObjectProvider instance
   */
  Pkcs11ObjectProvider<PkiCredential> getCredentialProvider();

}
