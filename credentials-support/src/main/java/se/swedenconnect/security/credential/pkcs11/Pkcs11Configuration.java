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
package se.swedenconnect.security.credential.pkcs11;

import jakarta.annotation.Nonnull;

import java.security.Provider;

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
  @Nonnull
  Provider getProvider() throws Pkcs11ConfigurationException;

}
