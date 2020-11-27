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

import java.security.InvalidParameterException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.credential.KeyPairCredential;
import se.swedenconnect.security.credential.KeyStoreCredential;

/**
 * The default PKCS#11 configuration class. This implementation assumes that the SunPKCS11 security provider is used.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class DefaultPkcs11Configuration extends AbstractPkcs11Configuration {

  /** The security provider for this configuration. */
  private Provider provider;

  /**
   * Default constructor.
   */
  public DefaultPkcs11Configuration() {
  }

  /**
   * Constructor assigning the external PKCS#11 configuration file.
   * 
   * @param configurationFile
   *          complete path to the PKCS#11 configuration file
   * @throws Pkcs11ConfigurationException
   *           if the supplied configuration file does not exist
   */
  public DefaultPkcs11Configuration(final String configurationFile) throws Pkcs11ConfigurationException {
    super(configurationFile);
  }

  /**
   * A constructor setting the library, name, slot and slotListIndex individually. See also
   * {@link #DefaultPkcs11FileConfiguration(String)}.
   * 
   * @param library
   *          the PKCS#11 library path
   * @param name
   *          the name of the HSM slot
   * @param slot
   *          the slot number/id (may be null)
   * @param slotListIndex
   *          the slot index (may be null)
   */
  public DefaultPkcs11Configuration(final String library, final String name, final String slot, final Integer slotListIndex) {
    super(library, name, slot, slotListIndex);
  }

  /** {@inheritDoc} */
  @Override
  public synchronized Provider getProvider() throws Pkcs11ConfigurationException {

    if (this.provider != null) {
      return this.provider;
    }

    // Create a SunPKCS11 provider ...
    //
    Provider p = Security.getProvider("SunPKCS11");
    if (p == null) {
      throw new Pkcs11ConfigurationException("Failed to get a SunPKCS11 provider");
    }

    // Configure it, and get a new provider instance ...
    //
    final String configData = this.getConfigurationData();
    log.debug("Configuring SunPKCS11 provider with the following configuration data: {}", configData);
    try {
      p = p.configure(configData);
    }
    catch (InvalidParameterException e) {
      throw new Pkcs11ConfigurationException("Failed to configure SunPKCS11 provider", e);
    }
    log.debug("SunPKCS11 provider successfully configured - Provider name: {}", p.getName());

    // Install it ...
    //
    final int result = Security.addProvider(p);
    if (result == -1) {
      log.warn("A provider with the name '{}' has already been installed", p.getName());
    }

    this.provider = p;
    return this.provider;
  }

  /** {@inheritDoc} */
  @Override
  public Pkcs11ObjectProvider<PrivateKey> getPrivateKeyProvider() {

    return (provider, alias, pin) -> {
      try {
        log.debug("Creating a PKCS11 KeyStore using provider '{}' ...", provider.getName());
        KeyStore keyStore = KeyStore.getInstance("PKCS11", provider.getName());

        log.debug("Loading KeyStore using supplied PIN ...");
        keyStore.load(null, pin);

        log.debug("Getting private key from entry '{}' ...", alias);
        PrivateKey pk = (PrivateKey) keyStore.getKey(alias, pin);

        if (pk != null) {
          log.debug("Private key was successfully obtained from device at alias '{}' using provider '{}'", alias, provider.getName());
        }
        else {
          log.debug("No private key was found on device at alias '{}' using provider '{}'", alias, provider.getName());
        }
        return pk;
      }
      catch (Exception e) {
        throw new SecurityException(
          String.format("Failed to load private key from provider '%s' - {}", provider.getName(), e.getMessage()), e);
      }
    };
  }

  /** {@inheritDoc} */
  @Override
  public Pkcs11ObjectProvider<KeyPairCredential> getKeyPairProvider() {
    return (provider, alias, pin) -> {
      try {
        KeyStoreCredential cred = new KeyStoreCredential(null, "PKCS11", provider.getName(), pin, alias, pin);
        cred.afterPropertiesSet();
        return cred;
      }
      catch (Exception e) {
        throw new SecurityException(
          String.format("Failed to load private key and certificate from provider '%s' - {}", provider.getName(), e.getMessage()), e);
      }
    };
  }

  /**
   * Gets the configuration data for this configuration. The data returned is supplied in the
   * {@link Provider#configure(String)} call that is made to configure the PKCS#11 security provider.
   * <p>
   * The returned string represents either a file name to an PKCS#11 configuration file or PKCS#11 configuration
   * commands (in that case the string must be prefixed with {@code --}.
   * </p>
   * 
   * @return configuration data for a PKCS#11 provider
   * @throws Pkcs11ConfigurationException
   *           if the configuration is not valid
   */
  protected String getConfigurationData() throws Pkcs11ConfigurationException {
    this.afterPropertiesSet();

    if (this.getConfigurationFile() != null) {
      return this.getConfigurationFile();
    }

    // Manual configuration ...
    // See https://stackoverflow.com/questions/46521791/sunpkcs11-provider-in-java-9.
    //
    StringBuffer sb = new StringBuffer("--");
    sb.append("library = ").append(this.getLibrary()).append(System.lineSeparator());
    sb.append("name = ").append(this.getName()).append(System.lineSeparator());

    if (this.getSlot() != null) {
      sb.append("slot = ").append(this.getSlot()).append(System.lineSeparator());
    }
    if (this.getSlotListIndex() != null) {
      sb.append("slotListIndex = ").append(this.getSlotListIndex()).append(System.lineSeparator());
    }

    return sb.toString();
  }

}
