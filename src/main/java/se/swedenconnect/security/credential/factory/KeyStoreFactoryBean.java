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

import java.io.InputStream;
import java.security.KeyStore;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Optional;

import org.springframework.beans.factory.config.AbstractFactoryBean;
import org.springframework.core.io.Resource;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import lombok.extern.slf4j.Slf4j;

/**
 * Factory bean for creating and unlocking a {@link KeyStore}.
 * <p>
 * For Shibboleth users: <br>
 * Basically this class is the same as {@code net.shibboleth.ext.spring.factory.KeyStoreFactoryBean} from the
 * {@code net.shibboleth.ext:spring-extensions} library. However, using this class you can also instantiate a PKCS#11
 * {@link KeyStore} which is not possible with the {@code net.shibboleth.ext.spring.factory.KeyStoreFactoryBean} since
 * it requires the {@code resource} property to be non-null.
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class KeyStoreFactoryBean extends AbstractFactoryBean<KeyStore> {

  /** The resource holding the keystore. */
  private Resource resource;

  /** The keystore password. */
  private char[] password;

  /** The type of keystore. */
  private String type;

  /** The name of the security provider to use when creating the KeyStore instance. */
  private String provider;

  /** The PKCS#11 configuration file to use. */
  private String pkcs11Configuration;

  /**
   * Default constructor.
   */
  public KeyStoreFactoryBean() {
  }

  /**
   * Constructor that accepts a resource reference a keystore and the password to unlock this file.
   * <p>
   * The type of {@link KeyStore} created will be {@link KeyStore#getDefaultType()}.
   * </p>
   *
   * @param resource
   *          the keystore resource
   * @param password
   *          the password for unlocking the keystore
   */
  public KeyStoreFactoryBean(final Resource resource, final char[] password) {
    this(resource, password, KeyStore.getDefaultType());
  }

  /**
   * Constructor that accepts a resource reference to a keystore, the password to unlock this file and the store type
   * ("JKS", "PKCS12", ...).
   *
   * @param resource
   *          the keystore resource
   * @param password
   *          the password for unlocking the keystore
   * @param type
   *          the type of keystore
   */
  public KeyStoreFactoryBean(final Resource resource, final char[] password, final String type) {
    this.resource = resource;
    this.password = password != null ? Arrays.copyOf(password, password.length) : null;
    this.type = type;
  }

  /** {@inheritDoc} */
  @Override
  protected KeyStore createInstance() throws Exception {
    try {
      if (this.type == null) {
        this.type = KeyStore.getDefaultType();
        log.debug("KeyStore type not given, defaulting to '{}'", this.type);
      }

      // If this is PKCS11, configure the provider ...
      //
      if ("PKCS11".equalsIgnoreCase(this.type)) {
        if (this.provider == null) {
          log.debug("PKCS#11 configuration is assigned - assuming SunPKCS11 provider");
          this.provider = "SunPKCS11";
        }
        Provider securityProvider = Security.getProvider(this.provider);
        if (securityProvider == null) {
          throw new NoSuchProviderException(String.format("Provider '%s' does not exist", this.provider));
        }
        if (!securityProvider.isConfigured()) {
          if (this.pkcs11Configuration == null) {
            throw new IllegalArgumentException("Missing pkcs11Configuration");
          }
          log.debug("Configuring security provider '{}' using '{}'", this.provider, this.pkcs11Configuration);
          securityProvider = securityProvider.configure(this.pkcs11Configuration);
          Security.addProvider(securityProvider);
          this.provider = securityProvider.getName();
          log.debug("After configuration of provider, the '{}' provider name will be used", this.provider);
        }
        else {
          if (this.pkcs11Configuration != null) {
            throw new IllegalArgumentException(String.format(
              "Security provider '%s' has already been configured - pkcs11Configuration should be null", this.provider));
          }
          log.debug("Security provider '{}' has been statically configured", this.provider);
        }
      }

      KeyStore keystore = this.provider != null
          ? KeyStore.getInstance(this.type, this.provider)
          : KeyStore.getInstance(this.type);

      if (this.resource != null) {
        try (InputStream is = this.resource.getInputStream()) {
          keystore.load(is, this.password);
        }
      }
      else {
        keystore.load(null, this.password);
      }

      return keystore;
    }
    finally {
      if (this.isSingleton()) {
        // We don't want to keep the password in memory longer than needed
        Arrays.fill(this.password, (char) 0);
      }
    }
  }

  /**
   * Gets the resource holding the KeyStore.
   *
   * @return the KeyStore resource
   */
  public Resource getResource() {
    return this.resource;
  }

  /**
   * Assigns the resource holding the KeyStore.
   *
   * @param resource
   *          the KeyStore resource
   */
  public void setResource(final Resource resource) {
    this.resource = resource;
  }

  /**
   * Gets the password for unlocking the keystore.
   *
   * @return the password for unlocking the keystore
   */
  public char[] getPassword() {
    return this.password;
  }

  /**
   * Assigns the password for unlocking the keystore.
   *
   * @param password
   *          the password to set
   */
  public void setPassword(final char[] password) {
    this.password = Optional.ofNullable(password).map(p -> Arrays.copyOf(p, p.length)).orElse(null);
  }

  /**
   * Gets the type of KeyStore. If not explicitly assigned, {@link KeyStore#getDefaultType()} will be returned.
   *
   * @return the type of the KeyStore
   */
  public String getType() {
    return this.type != null ? this.type : KeyStore.getDefaultType();
  }

  /**
   * Assigns the type of KeyStore.
   *
   * @param type
   *          the type of the KeyStore
   */
  public void setType(final String type) {
    this.type = type;
  }

  /**
   * Gets the name of the security {@link Provider} to use when instantiating the {@link KeyStore}. If not explicitly
   * assigned {@code null} is returned. This means that the first provider that can create a {@link KeyStore} of the
   * given type will be used.
   *
   * @return the name of the security provider to use, or null
   */
  public String getProvider() {
    return this.provider;
  }

  /**
   * Assigns the name of the security {@link Provider} to use when instantiating the {@link KeyStore}.
   *
   * @param provider
   *          the name of the security provider to use
   */
  public void setProvider(final String provider) {
    this.provider = provider;
  }

  /**
   * Gets the complete path to the PKCS#11 configuration file to use to configure the provider in the cases the type is
   * "PKCS11". If no configuration file is supplied the supplied provider ({@link #setProvider(String)}) must already
   * have been configured for use with a specific PKCS#11 configuration.
   *
   * @return a complete path to a PKCS#11 configuration file, or null
   */
  public String getPkcs11Configuration() {
    return this.pkcs11Configuration;
  }

  /**
   * Sets the complete path to the PKCS#11 configuration file to use to configure the provider in the cases the type is
   * "PKCS11". If no configuration file is supplied the supplied provider ({@link #setProvider(String)}) must already
   * have been configured for use with a specific PKCS#11 configuration.
   *
   * @param pkcs11Configuration
   *          a complete path to a PKCS#11 configuration file
   */
  public void setPkcs11Configuration(final String pkcs11Configuration) {
    this.pkcs11Configuration = pkcs11Configuration;
  }

  /** {@inheritDoc} */
  @Override
  public Class<?> getObjectType() {
    return KeyStore.class;
  }

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() throws Exception {
    if (!"PKCS11".equalsIgnoreCase(this.type)) {
      // We don't need a resource for the PKCS11 type ...
      Assert.notNull(this.resource, "The property 'resource' must be assigned");
    }
    Assert.notNull(this.password, "The property 'password' must be assigned");
    if (!StringUtils.hasText(this.type)) {
      this.type = KeyStore.getDefaultType();
      log.debug("Property 'type' was not assigned - defaulting to '{}'", this.type);
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
  }

}
