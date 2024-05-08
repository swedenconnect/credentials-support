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
package se.swedenconnect.security.credential.factory;

import lombok.Getter;
import lombok.Setter;
import org.springframework.core.io.Resource;
import org.springframework.util.StringUtils;

import java.util.List;

/**
 * A utility class that can be used as a configuration properties object for representing a credential (for Spring
 * Boot).
 *
 * @author Martin Lindström (martin@idsec.se)
 */
public class PkiCredentialConfigurationProperties {

  /**
   * The name of the credential.
   */
  @Getter
  @Setter
  private String name;

  /**
   * A resource holding the certificate part of the credential (optional since the certificate may be part of a
   * keystore).
   */
  @Getter
  @Setter
  private Resource certificate;

  /**
   * A list of resources holding the certificate chain that part of the credential (optional since the certificate may be part of a
   * keystore). If used, the entity certificate must be the first element.
   */
  @Getter
  @Setter
  private List<Resource> certificates;

  /**
   * A resource holding the private key part of the credential (optional since the key may be part of a keystore).
   */
  @Getter
  @Setter
  private Resource privateKey;

  /**
   * A resource to the keystore containing the credential.
   */
  @Getter
  @Setter
  private Resource resource;

  /**
   * The keystore password.
   */
  @Getter
  @Setter
  private char[] password;

  /**
   * The type of keystore.
   */
  @Getter
  @Setter
  private String type;

  /**
   * The name of the security provider to use when creating the KeyStore instance.
   */
  @Getter
  @Setter
  private String provider;

  /**
   * The PKCS#11 configuration file to use.
   */
  @Getter
  @Setter
  private String pkcs11Configuration;

  /**
   * The keystore alias to the entry holding the key pair.
   */
  @Getter
  @Setter
  private String alias;

  /**
   * The password to unlock the private key from the keystore.
   */
  @Getter
  @Setter
  private char[] keyPassword;

  /**
   * Assigns the PIN (which is the same as {@code keyPassword}. Used mainly for PKCS#11.
   *
   * @param pin
   *          the PIN
   */
  public void setPin(final char[] pin) {
    this.setKeyPassword(pin);
  }

  /**
   * Gets the PIN (which is the same as {@code keyPassword}). Used mainly for PKCS#11.
   *
   * @return the PIN
   */
  public char[] getPin() {
    return this.getKeyPassword();
  }

  /**
   * Predicate that returns {@code true} if this object is "empty", meaning that no settings have been applied.
   *
   * @return true if empty and false otherwise
   */
  public boolean isEmpty() {
    return !StringUtils.hasText(this.name)
        && this.certificate == null
        && (this.certificates == null || this.certificates.isEmpty())
        && this.privateKey == null
        && this.resource == null && (this.password == null || this.password.length == 0)
        && !StringUtils.hasText(this.type) && !StringUtils.hasText(this.provider)
        && !StringUtils.hasText(this.pkcs11Configuration) && !StringUtils.hasText(this.alias)
        && (this.keyPassword == null || this.keyPassword.length == 0);
  }

}
