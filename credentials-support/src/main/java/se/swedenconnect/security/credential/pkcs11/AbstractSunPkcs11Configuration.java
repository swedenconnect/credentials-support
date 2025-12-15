/*
 * Copyright 2020-2025 Sweden Connect
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
import jakarta.annotation.Nullable;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.InvalidParameterException;
import java.security.Provider;
import java.security.Security;
import java.util.Optional;

/**
 * Abstract base class for PKCS#11 configuration.
 * <p>
 * This implementation assumes that the SunPKCS11 security provider is used, or other security providers that supports
 * the {@link java.security.KeyStoreSpi}.
 * </p>
 * <p>
 * The method {@link #getBaseProviderName()} must be overridden if another security provider than SunPKCS11 is being
 * used.
 * </p>
 * <p>
 * See <a href="https://docs.oracle.com/en/java/javase/21/security/pkcs11-reference-guide1.html">PKCS#11 Reference
 * Guide</a>.
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public abstract class AbstractSunPkcs11Configuration implements Pkcs11Configuration {

  /** Logger instance. */
  private static final Logger log = LoggerFactory.getLogger(AbstractSunPkcs11Configuration.class);

  /** Default provider name. */
  public static final String DEFAULT_PROVIDER_NAME = "SunPKCS11";

  /** The security provider for this configuration. */
  private Provider provider;

  private final String baseProviderName;

  /**
   * Default constructor.
   */
  protected AbstractSunPkcs11Configuration() {
    this(DEFAULT_PROVIDER_NAME);
  }

  /**
   * Constructor setting the "base provider name".
   * <p>
   * Assigns the name of the security provider that we use to create new instances that have names according to
   * {@code <base-provider-name>-<instance-name>}, where 'instance-name' is gotten from the configuration.
   * Implementations wishing to use another provider than "SunPKCS11" should supply this provider name.
   * </p>
   *
   * @param baseProviderName the base provider name
   */
  protected AbstractSunPkcs11Configuration(@Nullable final String baseProviderName) {
    this.baseProviderName = Optional.ofNullable(baseProviderName).orElse(DEFAULT_PROVIDER_NAME);
  }

  /**
   * An init method that should be called to fully initialize the configuration object.
   *
   * @throws Pkcs11ConfigurationException for configuration errors
   */
  @PostConstruct
  public void init() throws Pkcs11ConfigurationException {
    if (this.provider == null) {
      this.getProvider();
    }
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public Provider getProvider() throws Pkcs11ConfigurationException {
    if (this.provider == null) {
      synchronized (this) {
        Provider p = Security.getProvider(this.getBaseProviderName());
        if (p == null) {
          throw new Pkcs11ConfigurationException(
              "Failed to get the '%s' provider".formatted(this.getBaseProviderName()));
        }
        if (p.isConfigured()) {
          if (this.getConfigurationData() != null) {
            throw new Pkcs11ConfigurationException(
                "Provider is statically configured - No configuratiom data must be supplied");
          }
          this.provider = p;
        }
        else if (this.getConfigurationData() == null) {
          throw new Pkcs11ConfigurationException("Missing configuration data");
        }
        else {
          // Configure it, and get a new provider instance ...
          //
          final String configData = this.getConfigurationData();
          log.debug("Configuring '{}' provider with the following configuration data: {}",
              this.getBaseProviderName(), configData);
          try {
            p = p.configure(configData);
          }
          catch (final InvalidParameterException e) {
            throw new Pkcs11ConfigurationException(
                "Failed to configure '%s' provider".formatted(this.getBaseProviderName()), e);
          }
          log.debug("{} provider successfully configured - Provider name: {}", this.getBaseProviderName(), p.getName());

          // Install it ...
          //
          final int result = Security.addProvider(p);
          if (result == -1) {
            log.info("A provider with the name '{}' has already been installed, re-using it ...", p.getName());
            this.provider = Security.getProvider(p.getName());
          }
          else {
            this.provider = p;
          }
        }
      }
    }
    return this.provider;
  }

  /**
   * Gets the name of the security provider that we use to create new instances that have names according to
   * {@code <base-provider-name>-<instance-name>}, where 'instance-name' is gotten from the configuration.
   *
   * @return the provider name (SunPKCS11 is used for the default implementation)
   */
  protected final String getBaseProviderName() {
    return this.baseProviderName;
  }

  /**
   * Gets the configuration data for this configuration. The data returned is supplied in the
   * {@link Provider#configure(String)} call that is made to configure the PKCS#11 security provider.
   * <p>
   * The returned string represents either a file name to an PKCS#11 configuration file or PKCS#11 configuration
   * commands (in that case the string must be prefixed with {@code --}.
   * </p>
   * <p>
   * Note: For configuration objects using a pre-configured security provider, the method must return {@code null}.
   * </p>
   *
   * @return configuration data for a PKCS#11 provider, or {@code null} if no configuration is needed
   */
  @Nullable
  protected abstract String getConfigurationData();

  /** {@inheritDoc} */
  @Override
  public String toString() {
    String providerName;
    try {
      final Provider provider = this.getProvider();
      providerName = provider.getName();
    }
    catch (final Exception e) {
      providerName = "unknown";
    }
    return "provider='%s'".formatted(providerName);
  }
}
