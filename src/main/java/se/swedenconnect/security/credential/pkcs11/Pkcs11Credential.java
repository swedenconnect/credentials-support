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

import java.security.KeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

import org.springframework.util.Assert;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.credential.AbstractKeyPairCredential;
import se.swedenconnect.security.credential.KeyPairCredential;
import se.swedenconnect.security.credential.monitoring.DefaultCredentialTestFunction;
import se.swedenconnect.security.credential.pkcs11.configuration.DefaultPkcs11Configuration;
import se.swedenconnect.security.credential.pkcs11.configuration.Pkcs11Configuration;
import se.swedenconnect.security.credential.pkcs11.configuration.Pkcs11ConfigurationException;

/**
 * A PKCS#11 credential implementation of the {@link KeyPairCredential} interface.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class Pkcs11Credential extends AbstractKeyPairCredential {

  /** The PKCS#11 configuration for the token that holds this credential. */
  private Pkcs11Configuration configuration;

  /** The alias of the key pair on the token. */
  private String alias;

  /** The PIN (key password) needed to unlock the token. */
  private char[] pin;

  /** Whether the credential has been loaded? */
  private boolean loaded = false;

  /**
   * Default constructor.
   */
  public Pkcs11Credential() {
  }

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
   */
  public Pkcs11Credential(final Pkcs11Configuration configuration, final String alias, final char[] pin,
      final X509Certificate certificate) {

    this.setConfiguration(configuration);
    this.setAlias(alias);
    this.setPin(pin);
    this.setCertificate(certificate);
  }

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() throws Exception {
    Assert.notNull(this.configuration, "'configuration' must not be null");
    Assert.hasText(this.alias, "'alias' must be set");
    Assert.notNull(this.pin, "'pin' must not be null");
    
    this.load();
  }

  /** {@inheritDoc} */
  @Override
  public void destroy() {
    if (this.pin != null) {
      Arrays.fill(this.pin, (char) 0);
    }
  }

  /**
   * Loads the credential.
   * 
   * @throws IllegalArgumentException
   *           for missing properties
   * @throws SecurityException
   *           for errors loading the credential
   */
  private synchronized void load() throws IllegalArgumentException, SecurityException {
    if (this.loaded) {
      return;
    }

    // Set the 'loaded' flag before we load. If the loading fails we don't want to keep loading and loading ...
    //
    this.loaded = true;

    // Load the private key (and possibly the certificate) ...
    //
    PrivateKey pk = null;
    X509Certificate cert = super.getCertificate();
    if (cert != null) {
      pk = this.configuration.getPrivateKeyProvider().get(this.configuration.getProvider(), this.alias, this.pin);
    }
    else {
      final KeyPairCredential cred = this.configuration.getKeyPairProvider().get(this.configuration.getProvider(), this.alias, this.pin);
      if (cred != null) {
        pk = cred.getPrivateKey();
        cert = cred.getCertificate();
      }
    }
    if (pk == null) {
      throw new IllegalArgumentException(String.format("No private key found under alias '%s'", this.alias));
    }
    if (cert == null) {
      throw new IllegalArgumentException(String.format("No certificate supplied and none found under alias '%s'", this.alias));
    }
    super.setPrivateKey(pk);
    this.setCertificate(cert);
    
    // Install a default test function (if none has been set) ...
    //
    if (this.getTestFunction() == null) {
      final DefaultCredentialTestFunction testFunction = new DefaultCredentialTestFunction();
      testFunction.setProvider(this.configuration.getProvider().getName());
      this.setTestFunction(testFunction);
    }
  }

  /** {@inheritDoc} */
  @Override
  public synchronized PrivateKey getPrivateKey() {
    if (!this.loaded) {
      log.warn("Pkcs11Credential '{}' has not been loaded ...", this.getName());
      try {
        this.load();
      }
      catch (Exception e) {
        log.error("Failed to load Pkcs11Credential '{}'", this.getName(), e);
        throw new SecurityException("Failed to load Pkcs11Credential - " + e.getMessage(), e);
      }
    }
    return super.getPrivateKey();
  }

  /**
   * Will throw an {@link IllegalArgumentException} since the private key will be read from the device.
   */
  @Override
  public void setPrivateKey(final PrivateKey privateKey) {
    throw new IllegalArgumentException("Assigning the private key for a Pkcs11Credential is not allowed");
  }

  /**
   * Will throw an {@link IllegalArgumentException} since the public key will be read from the certificate.
   */
  @Override
  public void setPublicKey(final PublicKey publicKey) {
    throw new IllegalArgumentException("Assigning the public key for a Pkcs11Credential is not allowed");
  }

  /** {@inheritDoc} */
  @Override
  public synchronized X509Certificate getCertificate() {
    if (!this.loaded) {
      log.warn("Pkcs11Credential '{}' has not been loaded ...", this.getName());
      try {
        this.load();
      }
      catch (Exception e) {
        log.error("Failed to load Pkcs11Credential '{}'", this.getName(), e);
        throw new SecurityException("Failed to load Pkcs11Credential - " + e.getMessage(), e);
      }
    }
    return super.getCertificate();
  }

  /**
   * Assigns the PKCS#11 configuration for the token that holds this credential.
   * 
   * @param configuration
   *          the configuration
   */
  public void setConfiguration(final Pkcs11Configuration configuration) {
    this.configuration = configuration;
  }

  /**
   * Assigns the PKCS#11 configuration file to use.
   * <p>
   * Note: An instance of {@link DefaultPkcs11Configuration} will be created. This assumes the use of the SunPKCS11
   * security provider. If another provider is desired, use the {@link #setConfiguration(Pkcs11Configuration)} instead.
   * </p>
   * 
   * @param configurationFile
   *          complete path to the PKCS#11 configuration file
   * @throws Pkcs11ConfigurationException
   *           if the configuration file is invalid
   */
  public void setConfiguration(final String configurationFile) throws Pkcs11ConfigurationException {
    try {
      final DefaultPkcs11Configuration conf = new DefaultPkcs11Configuration(configurationFile);
      conf.afterPropertiesSet();
      this.configuration = conf;
    }
    catch (Exception e) {
      if (Pkcs11ConfigurationException.class.isInstance(e)) {
        throw Pkcs11ConfigurationException.class.cast(e);
      }
      else {
        throw new Pkcs11ConfigurationException("Invalid PKCS#11 configuration", e);
      }
    }
  }

  /**
   * Assigns the alias of the key pair on the token.
   * 
   * @param alias
   *          the alias
   */
  public void setAlias(final String alias) {
    this.alias = Optional.ofNullable(alias).map(a -> a.trim()).orElse(null);
  }

  /**
   * Assigns the PIN (key password) needed to unlock the token.
   * 
   * @param pin
   *          the PIN
   */
  public void setPin(final char[] pin) {
    this.pin = Optional.ofNullable(pin).map(p -> Arrays.copyOf(p, p.length)).orElse(null);
  }

  /**
   * Is called if the connection to the device has been lost. In those cases we reload the private key.
   */
  @Override
  public synchronized void reload() throws Exception {
    //
    // Note: We log only on trace level since the monitor driving the reloading is responsible
    // of the actual logging.
    //    
    if (this.configuration == null || this.alias == null || this.pin == null) {
      throw new SecurityException("Error in reload - Pkcs11Credential has not been initialized yet");
    }
    log.trace("Reloading private key under alias '{}' for provider '{}' ...", this.alias, this.configuration.getProvider().getName());

    final PrivateKey pk = this.configuration.getPrivateKeyProvider().get(this.configuration.getProvider(), this.alias, this.pin);
    if (pk == null) {
      final String msg = String.format("No private key found under alias '%s' for provider '%s'",
        this.alias, this.configuration.getProvider().getName());
      log.trace("{}", msg);
      throw new KeyException(msg);
    }
    super.setPrivateKey(pk);

    log.trace("Private key under alias '{}' for provider '{}' was reloaded", this.alias, this.configuration.getProvider().getName());
  }

  /** {@inheritDoc} */
  @Override
  protected String getDefaultName() {
    StringBuffer sb = new StringBuffer();
    sb.append(this.configuration != null ? this.configuration.getProvider().getName() : "Pkcs11Credential")
      .append("-")
      .append(this.alias != null ? this.alias : UUID.randomUUID().toString());
    return sb.toString();
  }

}
