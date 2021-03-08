/*
 * Copyright 2020-2021 Sweden Connect
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

import java.io.InputStream;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Optional;

import org.opensaml.security.crypto.KeySupport;
import org.springframework.beans.factory.config.AbstractFactoryBean;
import org.springframework.core.io.Resource;
import org.springframework.util.StringUtils;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.credential.AbstractPkiCredential;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.Pkcs11Credential;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * A utility factory that can create any type of {@link PkiCredential} class defined in this module.
 * <p>
 * The logic is as follows:
 * </p>
 * <ul>
 * <li>A {@link BasicCredential} object is created if both a private key and a certificate has been assigned
 * ({@link #setPrivateKey(Resource)} and {@link #setCertificate(Resource)}).</li>
 * <li>A {@link Pkcs11Credential} object is created if the PKCS#11 configuration, alias and PIN (or key password) are
 * set ({@link #setPkcs11Configuration(String)}, {@link #setAlias(String)}, {@link #setPin(char[])}). If type is set
 * ({@link #setType(String)}), this must be set to "PKCS11".</li>
 * <li>A {@link KeyStoreCredential} object is created if the keystore resource, the password and alias are set
 * ({@link #setResource(Resource)}, {@link #setPassword(char[])}, {@link #setAlias(String)}).</li>
 * <li>If none of the above matches an error is thrown.</li>
 * </ul>
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class PkiCredentialFactoryBean extends AbstractFactoryBean<PkiCredential> {

  /** The name of the credential. */
  private String name;

  /**
   * A resource holding the certificate part of the credential (optional since the certificate may be part of a
   * keystore).
   */
  private Resource certificate;

  /** A resource holding the private key part of the credential (optional since the key may be part of a keystore). */
  private Resource privateKey;

  /** A resource to the keystore containing the credential. */
  private Resource resource;

  /** The keystore password. */
  private char[] password;

  /** The type of keystore. */
  private String type;

  /** The name of the security provider to use when creating the KeyStore instance. */
  private String provider;

  /** The PKCS#11 configuration file to use. */
  private String pkcs11Configuration;

  /** The keystore alias to the entry holding the key pair. */
  private String alias;

  /** The password to unlock the private key from the keystore. */
  private char[] keyPassword;

  /** {@inheritDoc} */
  @Override
  protected PkiCredential createInstance() throws Exception {

    AbstractPkiCredential credential = null;

    if (this.certificate != null && this.privateKey != null) {
      PrivateKey _privateKey = null;
      try (InputStream is = this.privateKey.getInputStream()) {
        _privateKey = KeySupport.decodePrivateKey(is, null);
      }
      credential = new BasicCredential(this.certificate, _privateKey);
    }
    else if (StringUtils.hasText(this.pkcs11Configuration) && StringUtils.hasText(this.alias) && this.keyPassword != null
        && (!StringUtils.hasText(this.type) || "PKCS11".equalsIgnoreCase(this.type))) {
      Pkcs11Credential p11Cred = new Pkcs11Credential();
      p11Cred.setConfigurationFile(this.pkcs11Configuration);
      p11Cred.setAlias(this.alias);
      p11Cred.setPin(this.keyPassword);
      if (this.certificate != null) {
        p11Cred.setCertificate(this.certificate);
      }
      credential = p11Cred;
    }
    else if (this.resource != null && this.password != null && this.alias != null) {
      KeyStoreCredential ksCred = new KeyStoreCredential();
      ksCred.setResource(this.resource);
      ksCred.setPassword(this.password);
      ksCred.setAlias(this.alias);
      ksCred.setType(this.type);
      if (StringUtils.hasText(this.provider)) {
        ksCred.setProvider(this.provider);
      }
      ksCred.setKeyPassword(this.keyPassword);
      credential = ksCred;
    }

    if (credential == null) {
      // If afterPropertiesSet is called, we'll never end up here ...
      throw new SecurityException("PkiCredentialFactoryBean was not correctly configured");
    }

    // Assign the name (if set) ...
    if (StringUtils.hasText(this.name)) {
      credential.setName(this.name);
    }

    credential.afterPropertiesSet();

    return credential;
  }

  /** {@inheritDoc} */
  @Override
  public Class<?> getObjectType() {
    return PkiCredential.class;
  }

  /**
   * Assigns the name of the credential.
   * 
   * @param name
   *          the credential name
   */
  public void setName(final String name) {
    this.name = name;
  }

  /**
   * Assigns the resource holding the certificate part of the credential (optional since the certificate may be part of
   * a keystore).
   * 
   * @param certificate
   *          certificate resource
   */
  public void setCertificate(final Resource certificate) {
    this.certificate = certificate;
  }

  /**
   * Assigns the resource holding the private key part of the credential (optional since the key may be part of a
   * keystore).
   * 
   * @param privateKey
   *          private key resource
   */
  public void setPrivateKey(final Resource privateKey) {
    this.privateKey = privateKey;
  }

  /**
   * Assigns the resource to the keystore containing the credential.
   * 
   * @param resource
   *          the keystore resource
   */
  public void setResource(final Resource resource) {
    this.resource = resource;
  }

  /**
   * Assigns the keystore password.
   * 
   * @param password
   *          keystore password
   */
  public void setPassword(final char[] password) {
    this.password = Optional.ofNullable(password).map(p -> Arrays.copyOf(p, p.length)).orElse(null);
  }

  /**
   * Assigns the type of keystore.
   * 
   * @param type
   *          the keystore type
   */
  public void setType(final String type) {
    this.type = type;
  }

  /**
   * Assigns the name of the security provider to use when creating the KeyStore instance.
   * 
   * @param provider
   *          security provider name
   */
  public void setProvider(final String provider) {
    this.provider = provider;
  }

  /**
   * Assigns the PKCS#11 configuration file to use.
   * 
   * @param pkcs11Configuration
   *          PKCS#11 configuration file (full path)
   */
  public void setPkcs11Configuration(final String pkcs11Configuration) {
    this.pkcs11Configuration = pkcs11Configuration;
  }

  /**
   * Assigns the keystore alias to the entry holding the key pair.
   * 
   * @param alias
   *          keystore alias
   */
  public void setAlias(final String alias) {
    this.alias = alias;
  }

  /**
   * Assigns the password to unlock the private key from the keystore.
   * 
   * @param keyPassword
   *          the key password
   */
  public void setKeyPassword(final char[] keyPassword) {
    this.keyPassword = Optional.ofNullable(keyPassword).map(p -> Arrays.copyOf(p, p.length)).orElse(null);
  }

  /**
   * Assigns the PIN. The same as keyPassword (used mainly for PKCS#11 credentials).
   * 
   * @param pin
   *          the PIN
   */
  public void setPin(final char[] pin) {
    this.setKeyPassword(pin);
  }

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() throws Exception {
    if (this.certificate != null && this.privateKey != null) {
      log.debug("A BasicCredential will be created");
    }
    else if (StringUtils.hasText(this.pkcs11Configuration) && StringUtils.hasText(this.alias) && this.keyPassword != null
        && (!StringUtils.hasText(this.type) || "PKCS11".equalsIgnoreCase(this.type))) {
      log.debug("A Pkcs11Credential will be created");
    }
    else if (this.resource != null && this.password != null && this.alias != null) {
      log.debug("A KeyStoreCredential will be created");
    }
    else {
      throw new IllegalArgumentException("Missing credential configuration - cannot create");
    }
    super.afterPropertiesSet();
  }
  
  /** {@inheritDoc} */
  @Override
  public void destroy() throws Exception {
    super.destroy();
    if (this.password != null) {
      Arrays.fill(this.password, (char) 0);
    }
    if (this.keyPassword != null) {
      Arrays.fill(this.keyPassword, (char) 0);
    }
  }

}
