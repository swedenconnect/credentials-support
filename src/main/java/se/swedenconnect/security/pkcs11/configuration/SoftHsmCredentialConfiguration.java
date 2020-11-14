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

import org.apache.commons.lang.StringUtils;

import lombok.Builder;

/**
 * Configuration class for setting up keys and certificates to be loaded into Soft HSM.
 *
 * @author Stefan Santesson (stefan@idsec.se)
 * @author Martin Lindström (martin@idsec.se)
 */
@Builder
public class SoftHsmCredentialConfiguration {

  /** The name of the key. This name will be part of the PKCS#11 provider name used to access the key through Soft HSM. */
  private String name;

  /** The absolute path to a PEM encoded PKCS#8 key. */
  private String keyLocation;

  /** The absolute path to a PEM encoded X509 certificate for the specified key. */
  private String certLocation;

  /**
   * Default constructor.
   */
  public SoftHsmCredentialConfiguration() {
  }

  /**
   * All arguments constructor.
   *
   * @param name
   *          the name of the key. This name will be part of the PKCS#11 provider name used to access the key through
   *          Soft HSM
   * @param keyLocation
   *          the absolute path to a PEM encoded PKCS#8 key
   * @param certLocation
   *          the absolute path to a PEM encoded X509 certificate for the specified key
   */
  public SoftHsmCredentialConfiguration(final String name, final String keyLocation, final String certLocation) {
    this.name = name;
    this.keyLocation = keyLocation;
    this.certLocation = certLocation;
  }

  /**
   * Getter for the name of the credential key.
   * 
   * @return the key name
   */
  public String getName() {
    return this.name;
  }

  /**
   * Setter for the name of the credential key.
   * 
   * @param name
   *          the key name
   */
  public void setName(final String name) {
    this.name = StringUtils.trim(name);
  }

  /**
   * Getter for the credential key location.
   * 
   * @return the credential key location
   */
  public String getKeyLocation() {
    return this.keyLocation;
  }

  /**
   * Setter for credential key location.
   * 
   * @param keyLocation
   *          the credential key location
   */
  public void setKeyLocation(final String keyLocation) {
    this.keyLocation = StringUtils.trim(keyLocation);
  }

  /**
   * Getter for the credential certificate location.
   * 
   * @return the credential certificate location
   */
  public String getCertLocation() {
    return this.certLocation;
  }

  /**
   * Setter for the credential certificate location.
   * 
   * @param certLocation
   *          the credential certificate location
   */
  public void setCertLocation(final String certLocation) {
    this.certLocation = StringUtils.trim(certLocation);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return String.format("name='%s', keyLocation='%s', certLocation='%s')", 
      this.name, this.keyLocation, this.certLocation);
  }
}
