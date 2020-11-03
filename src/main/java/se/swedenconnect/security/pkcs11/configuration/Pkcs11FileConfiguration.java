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

/**
 * A PKCS#11 configuration object that uses an external PKCS#11 external configuration file.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class Pkcs11FileConfiguration implements Pkcs11Configuration {

  /** The complete path to the configuration file. */
  private final String configurationFile;

  /**
   * Constructor.
   * 
   * @param configurationFile
   *          complete path to the PKCS#11 configuration file
   */
  public Pkcs11FileConfiguration(final String configurationFile) {
    this.configurationFile = configurationFile;
  }

  /** {@inheritDoc} */
  @Override
  public String getConfigurationData() {
    return this.configurationFile;
  }

}
