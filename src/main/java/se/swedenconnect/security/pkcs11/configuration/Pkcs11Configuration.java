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
   */
  String getConfigurationData();

}
