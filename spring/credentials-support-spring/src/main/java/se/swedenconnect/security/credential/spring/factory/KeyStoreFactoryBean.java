/*
 * Copyright 2020-2026 Sweden Connect
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
package se.swedenconnect.security.credential.spring.factory;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.config.AbstractFactoryBean;
import org.springframework.core.io.Resource;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import se.swedenconnect.security.credential.factory.KeyStoreFactory;
import se.swedenconnect.security.credential.pkcs11.AbstractSunPkcs11Configuration;
import se.swedenconnect.security.credential.pkcs11.FilePkcs11Configuration;
import se.swedenconnect.security.credential.pkcs11.StaticPkcs11Configuration;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Optional;

/**
 * Factory bean for creating and unlocking a {@link KeyStore}.
 * <p>
 * For Shibboleth users: <br> Basically this class is the same as
 * {@code net.shibboleth.ext.spring.factory.KeyStoreFactoryBean} from the {@code net.shibboleth.ext:spring-extensions}
 * library. However, using this class you can also instantiate a PKCS#11 {@link KeyStore} which is not possible with the
 * {@code net.shibboleth.ext.spring.factory.KeyStoreFactoryBean} since it requires the {@code resource} property to be
 * non-null.
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
   * @param resource the keystore resource
   * @param password the password for unlocking the keystore
   */
  public KeyStoreFactoryBean(@Nonnull final Resource resource, @Nonnull final char[] password) {
    this(resource, password, KeyStore.getDefaultType());
  }

  /**
   * Constructor that accepts a resource reference to a keystore, the password to unlock this file and the store type
   * ("JKS", "PKCS12", ...).
   *
   * @param resource the keystore resource (may be {@code null} if type is "PKCS11")
   * @param password the password for unlocking the keystore
   * @param type the type of keystore
   */
  public KeyStoreFactoryBean(
      @Nullable final Resource resource, @Nonnull final char[] password, @Nullable final String type) {
    this.resource = resource;
    this.password = password != null ? Arrays.copyOf(password, password.length) : null;
    this.type = type;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected KeyStore createInstance() throws Exception {
    try {
      if (KeyStoreFactory.PKCS11_KEYSTORE_TYPE.equals(this.getType())) {
        if (this.provider == null) {
          log.debug("PKCS#11 configuration is assigned - assuming SunPKCS11 provider");
          this.provider = "SunPKCS11";
        }
        final Provider securityProvider = Security.getProvider(this.provider);
        if (securityProvider == null) {
          throw new NoSuchProviderException(String.format("Provider '%s' does not exist", this.provider));
        }
        final AbstractSunPkcs11Configuration p11Configuration;
        if (securityProvider.isConfigured()) {
          if (this.pkcs11Configuration != null) {
            throw new IllegalArgumentException(String.format(
                "Security provider '%s' has already been configured - pkcs11Configuration should be null",
                this.provider));
          }
          p11Configuration = new StaticPkcs11Configuration(this.provider);
        }
        else {
          if (this.pkcs11Configuration == null) {
            throw new IllegalArgumentException("Missing pkcs11Configuration");
          }
          p11Configuration = new FilePkcs11Configuration(this.pkcs11Configuration, this.provider);
        }

        return KeyStoreFactory.loadPkcs11KeyStore(p11Configuration, this.password);
      }
      else {
        if (this.resource == null) {
          throw new IllegalArgumentException("Missing resource");
        }
        try (final InputStream is = this.resource.getInputStream()) {
          return KeyStoreFactory.loadKeyStore(is, this.password, this.getType(), this.getProvider());
        }
      }
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
  @Nullable
  public Resource getResource() {
    return this.resource;
  }

  /**
   * Assigns the resource holding the KeyStore.
   *
   * @param resource the KeyStore resource
   */
  public void setResource(@Nonnull final Resource resource) {
    this.resource = resource;
  }

  /**
   * Gets the password for unlocking the keystore.
   *
   * @return the password for unlocking the keystore
   */
  @Nullable
  public char[] getPassword() {
    return this.password;
  }

  /**
   * Assigns the password for unlocking the keystore.
   *
   * @param password the password to set
   */
  public void setPassword(@Nonnull final char[] password) {
    this.password = Optional.ofNullable(password).map(p -> Arrays.copyOf(p, p.length)).orElse(null);
  }

  /**
   * Gets the type of KeyStore. If not explicitly assigned, {@link KeyStore#getDefaultType()} will be returned.
   *
   * @return the type of the KeyStore
   */
  @Nonnull
  public String getType() {
    return this.type != null ? this.type : KeyStore.getDefaultType();
  }

  /**
   * Assigns the type of KeyStore.
   *
   * @param type the type of the KeyStore
   */
  public void setType(@Nonnull final String type) {
    this.type = type;
  }

  /**
   * Gets the name of the security {@link Provider} to use when instantiating the {@link KeyStore}. If not explicitly
   * assigned {@code null} is returned. This means that the first provider that can create a {@link KeyStore} of the
   * given type will be used.
   *
   * @return the name of the security provider to use, or null
   */
  @Nullable
  public String getProvider() {
    return this.provider;
  }

  /**
   * Assigns the name of the security {@link Provider} to use when instantiating the {@link KeyStore}.
   *
   * @param provider the name of the security provider to use
   */
  public void setProvider(@Nonnull final String provider) {
    this.provider = provider;
  }

  /**
   * Gets the complete path to the PKCS#11 configuration file to use to configure the provider in the cases the type is
   * "PKCS11". If no configuration file is supplied the supplied provider ({@link #setProvider(String)}) must already
   * have been configured for use with a specific PKCS#11 configuration.
   *
   * @return a complete path to a PKCS#11 configuration file, or null
   */
  @Nullable
  public String getPkcs11Configuration() {
    return this.pkcs11Configuration;
  }

  /**
   * Sets the complete path to the PKCS#11 configuration file to use to configure the provider in the cases the type is
   * "PKCS11". If no configuration file is supplied the supplied provider ({@link #setProvider(String)}) must already
   * have been configured for use with a specific PKCS#11 configuration.
   *
   * @param pkcs11Configuration a complete path to a PKCS#11 configuration file
   */
  public void setPkcs11Configuration(@Nonnull final String pkcs11Configuration) {
    this.pkcs11Configuration = pkcs11Configuration;
  }

  /** {@inheritDoc} */
  @Nonnull
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
