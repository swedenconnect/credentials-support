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
package se.swedenconnect.security.credential.pkcs11conf;

import java.security.InvalidParameterException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * The default PKCS#11 configuration class. This implementation assumes that the SunPKCS11 security provider is used.
 * <p>
 * The SunPKCS11 provider can be configured programatically (using any of the setters or appropriate constructors). In
 * these cases the first call to {@link #getProvider()} returns a configured and ready-to-use provider based on the
 * assigned configuration.
 * </p>
 * <p>
 * A SunPKCS11 provider can also be statically configured in the {@code java.security} file. For example:
 * </p>
 * 
 * <pre>
 * ...
 * security.provider.13=SunPKCS11 /opt/bar/cfg/pkcs11.cfg
 * ...
 * </pre>
 * <p>
 * In these cases the {@code DefaultPkcs11Configuration} should be used with no configuration assigned.
 * </p>
 * <p>
 * For more information, see the
 * <a href="https://docs.oracle.com/en/java/javase/14/security/pkcs11-reference-guide1.html">PKCS#11 Reference
 * Guide</a>.
 * </p>
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class DefaultPkcs11Configuration extends AbstractPkcs11Configuration {

  /** The security provider for this configuration. */
  private Provider provider;

  /**
   * The name of the SunPKCS11 security provider that we use to create new instances that have names according to
   * "SunPKCS11-name", where 'name' is gotten from the configuration. The reason this is not a constant is for testing
   * purposes where we want to use a mocked provider instead of Sun's.
   */
  private String baseProviderName = "SunPKCS11";

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
   * {@link #DefaultPkcs11Configuration(String)}.
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
  public void afterPropertiesSet() throws Pkcs11ConfigurationException {

    final Provider p = Security.getProvider(this.getBaseProviderName());
    if (p == null) {
      throw new Pkcs11ConfigurationException(String.format("Failed to get the %s provider", this.getBaseProviderName()));
    }
    if (p.isConfigured()) {
      // If a statically configured provider is used, we don't allow anything to be configured.
      //
      if (this.getConfigurationFile() != null || this.getLibrary() != null || this.getName() != null
          || this.getSlot() != null || this.getSlotListIndex() != null) {
        throw new Pkcs11ConfigurationException(
          "Provider is statically configured - DefaultPkcs11Configuration must not have any configuration");
      }
      this.provider = p;
    }
    else {
      super.afterPropertiesSet();
    }
  }

  /** {@inheritDoc} */
  @Override
  public synchronized Provider getProvider() throws Pkcs11ConfigurationException {

    if (this.provider != null) {
      return this.provider;
    }

    // Create a SunPKCS11 provider ...
    //
    Provider p = Security.getProvider(this.getBaseProviderName());
    if (p == null) {
      throw new Pkcs11ConfigurationException(String.format("Failed to get the %s provider", this.getBaseProviderName()));
    }

    if (!p.isConfigured()) {
      // Configure it, and get a new provider instance ...
      //
      final String configData = this.getConfigurationData();
      log.debug("Configuring {} provider with the following configuration data: {}", this.getBaseProviderName(), configData);
      try {
        p = p.configure(configData);
      }
      catch (InvalidParameterException e) {
        throw new Pkcs11ConfigurationException(String.format("Failed to configure %s provider", this.getBaseProviderName()), e);
      }
      log.debug("{} provider successfully configured - Provider name: {}", this.getBaseProviderName(), p.getName());

      // Install it ...
      //
      final int result = Security.addProvider(p);
      if (result == -1) {
        log.warn("A provider with the name '{}' has already been installed", p.getName());
      }
    }
    else {
      log.debug("The {} provider has already been configured ...", this.getBaseProviderName());
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
  public Pkcs11ObjectProvider<PkiCredential> getCredentialProvider() {
    return (provider, alias, pin) -> {
      try {
        log.debug("Creating a PKCS11 KeyStore using provider '{}' ...", provider.getName());
        KeyStore keyStore = KeyStore.getInstance("PKCS11", provider.getName());

        log.debug("Loading KeyStore using supplied PIN ...");
        keyStore.load(null, pin);

        log.debug("Getting private key from entry '{}' ...", alias);
        final PrivateKey pk = (PrivateKey) keyStore.getKey(alias, pin);

        if (pk != null) {
          log.debug("Private key was successfully obtained from device at alias '{}' using provider '{}'", alias, provider.getName());
        }
        else {
          log.debug("No private key was found on device at alias '{}' using provider '{}'", alias, provider.getName());
          return null;
        }

        final X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
        if (cert != null) {
          log.debug("Certificate was successfully obtained from device at alias '{}' using provider '{}'", alias, provider.getName());
        }
        else {
          log.debug("No certificate was found on device at alias '{}' using provider '{}'", alias, provider.getName());
        }
        return new BasicCredential(cert, pk);
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
    try {
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
    catch (Exception e) {
      throw new Pkcs11ConfigurationException(e.getMessage(), e);
    }
  }

  /**
   * Assigns name of the SunPKCS11 security provider that we use to create new instances that have names according to
   * "SunPKCS11-name", where 'name' is gotten from the configuration. The reason this is not a constant is for testing
   * purposes where we want to use a mocked provider instead of Sun's.
   * <p>
   * NOTE: FOR TESTING ONLY.
   * </p>
   * 
   * @param baseProviderName
   *          the provider name.
   */
  public void setBaseProviderName(final String baseProviderName) {
    this.baseProviderName = baseProviderName;
  }

  /**
   * Gets the provider name (see {@link #setBaseProviderName(String)}).
   * 
   * @return the provider name
   */
  protected String getBaseProviderName() {
    return this.baseProviderName != null ? this.baseProviderName : "SunPKCS11";
  }

}
