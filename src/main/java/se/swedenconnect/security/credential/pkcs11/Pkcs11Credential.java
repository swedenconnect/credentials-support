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
package se.swedenconnect.security.credential.pkcs11;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Optional;

import org.apache.commons.lang.StringUtils;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.credential.KeyPairCredential;
import se.swedenconnect.security.credential.pkcs11.configuration.Pkcs11Configuration;

/**
 * A PKCS#11 credential implementation of the {@link KeyPairCredential} interface.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class Pkcs11Credential implements KeyPairCredential {

  /** The PKCS#11 configuration for the token that holds this credential. */
  private final Pkcs11Configuration configuration;

  /** The alias of the key pair on the token. */
  private final String alias;

  /** The PIN (key password) needed to unlock the token. */
  private final char[] pin;
  
  /** The name of the credential. */
  private String name;

  /** If the certificate is not placed on the HSM it is supplied explicitly. */
  private X509Certificate certificate;

  /** The private key. */
  private PrivateKey privateKey;

  /**
   * Constructor.
   * 
   * @param configuration
   *          the PKCS#11 configuration
   * @param alias
   *          the token entry from where to load the private key and certificate
   * @param pin
   *          the PIN to unlock the token
   * @throws IllegalArgumentException
   *           for missing parameters
   * @throws SecurityException
   *           if loading of the private key and/or certificate fails
   */
  public Pkcs11Credential(final Pkcs11Configuration configuration, final String alias, final char[] pin)
      throws IllegalArgumentException, SecurityException {

    this(configuration, alias, pin, null);
  }

  /**
   * Constructor that takes a X.509 certificate as an argument. This constructor should be used if we know that the
   * certificate is not placed on the device (only the private key).
   * 
   * @param configuration
   *          the PKCS#11 configuration
   * @param alias
   *          the token entry from where to load the private key
   * @param pin
   *          the PIN to unlock the token
   * @param certificate
   *          the certificate
   * @throws IllegalArgumentException
   *           for missing parameters
   * @throws SecurityException
   *           if loading of the private key fails
   */
  public Pkcs11Credential(final Pkcs11Configuration configuration, final String alias, final char[] pin, final X509Certificate certificate)
      throws IllegalArgumentException, SecurityException {

    this.configuration = Optional.ofNullable(configuration)
      .orElseThrow(() -> new IllegalArgumentException("configuration must not be null"));
    this.alias = Optional.ofNullable(alias).filter(a -> StringUtils.isNotBlank(a)).map(a -> a.trim())
      .orElseThrow(() -> new IllegalArgumentException("alias must not be null or empty"));
    this.pin = Optional.ofNullable(pin).filter(p -> p.length > 0).map(p -> p.clone())
      .orElseThrow(() -> new IllegalArgumentException("pin must not be null or empty"));
    this.certificate = certificate;

    // Load the private key (and possibly the certificate) ...
    //
    if (this.certificate != null) {
      this.privateKey = this.configuration.getPrivateKeyProvider().get(this.configuration.getProvider(), this.alias, this.pin);
    }
    else {
      KeyPairCredential cred = this.configuration.getKeyPairProvider().get(this.configuration.getProvider(), this.alias, this.pin);
      if (cred != null) {
        this.privateKey = cred.getPrivateKey();
        this.certificate = cred.getCertificate();
      }
    }
    if (this.privateKey == null) {
      throw new IllegalArgumentException(String.format("No private key found under alias '%s'", this.alias));
    }
    if (this.certificate == null) {
      throw new IllegalArgumentException(String.format("No certificate supplied and none found under alias '%s'", this.alias));
    }
    
    
  }

  /** {@inheritDoc} */
  @Override
  public PublicKey getPublicKey() {
    return this.certificate.getPublicKey();
  }

  /** {@inheritDoc} */
  @Override
  public X509Certificate getCertificate() {
    return this.certificate;
  }

  /** {@inheritDoc} */
  @Override
  public synchronized PrivateKey getPrivateKey() {
    return this.privateKey;
  }
  
  /**
   * Gets the name of the credential. Defauls to <provider name>-<alias>.
   */
  @Override
  public String getName() {
    if (this.name == null) {
      this.name = String.format("%s-%s", this.configuration.getProvider().getName(), this.alias);
    }
    return this.name;
  }

  /**
   * Assigns the name of the credential.
   * 
   * @param name the name
   */
  public void setName(final String name) {
    this.name = name;
  }

  /**
   * Is called if the connection to the device has been lost. In those cases we reload the private key.
   */
  @Override
  public void reload() throws SecurityException {
    log.info("Reloading private key under alias '{}' for provider '{}' ...", this.alias, this.configuration.getProvider().getName());

    synchronized (this) {
      final PrivateKey pk = this.configuration.getPrivateKeyProvider().get(this.configuration.getProvider(), this.alias, this.pin);
      if (pk == null) {
        final String msg = String.format("No private key found under alias '%s' for provider '%s'",
          this.alias, this.configuration.getProvider().getName());
        log.error("{}", msg);
        throw new SecurityException(msg);
      }
      this.privateKey = pk;
    }
    log.info("Private key under alias '{}' for provider '{}' was reloaded", this.alias, this.configuration.getProvider().getName());
  }

}
