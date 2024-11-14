/*
 * Copyright 2020-2024 Sweden Connect
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
import org.springframework.beans.factory.config.AbstractFactoryBean;
import org.springframework.core.io.DefaultResourceLoader;
import se.swedenconnect.security.credential.KeyStoreReloader;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.config.ConfigurationResourceLoader;
import se.swedenconnect.security.credential.config.PemCredentialConfiguration;
import se.swedenconnect.security.credential.config.PkiCredentialConfiguration;
import se.swedenconnect.security.credential.config.StoreCredentialConfiguration;
import se.swedenconnect.security.credential.config.properties.PkiCredentialConfigurationProperties;
import se.swedenconnect.security.credential.factory.PkiCredentialFactory;
import se.swedenconnect.security.credential.spring.config.SpringConfigurationResourceLoader;

import java.security.KeyStore;
import java.util.Objects;
import java.util.function.Function;

/**
 * A {@link org.springframework.beans.factory.FactoryBean FactoryBean} for creating {@link PkiCredential} objects.
 *
 * @author Martin Lindström
 * @see se.swedenconnect.security.credential.factory.PkiCredentialFactory
 */
public class PkiCredentialFactoryBean extends AbstractFactoryBean<PkiCredential> {

  /** The configuration. */
  private final PkiCredentialConfiguration configuration;

  /** The resource loader. */
  private final ConfigurationResourceLoader resourceLoader;

  /** For loading stores from references. */
  private Function<String, KeyStore> keyStoreSupplier;

  /** For loading reloader implementations from key store references. */
  private Function<String, KeyStoreReloader> keyStoreReloaderSupplier;

  /**
   * Constructor aceepting a {@link PkiCredentialConfiguration}.
   *
   * @param configuration the configuration
   */
  public PkiCredentialFactoryBean(@Nonnull final PkiCredentialConfiguration configuration) {
    this.configuration = Objects.requireNonNull(configuration, "configuration must not be null");
    this.resourceLoader = new SpringConfigurationResourceLoader(new DefaultResourceLoader());
  }

  /**
   * Constructor aceepting a {@link StoreCredentialConfiguration}.
   *
   * @param configuration the configuration
   */
  public PkiCredentialFactoryBean(@Nonnull final StoreCredentialConfiguration configuration) {
    this(new PkiCredentialConfigurationProperties());
    ((PkiCredentialConfigurationProperties) this.configuration).setJks(
        Objects.requireNonNull(configuration, "configuration must not be null"));
  }

  /**
   * Constructor aceepting a {@link PemCredentialConfiguration}.
   *
   * @param configuration the configuration
   */
  public PkiCredentialFactoryBean(@Nonnull final PemCredentialConfiguration configuration) {
    this(new PkiCredentialConfigurationProperties());
    ((PkiCredentialConfigurationProperties) this.configuration).setPem(
        Objects.requireNonNull(configuration, "configuration must not be null"));
  }

  /**
   * If a store configuration is used that has a store reference, a key store supplier is needed.
   *
   * @param keyStoreSupplier provides a {@link KeyStore} based on its registered ID
   */
  public void setKeyStoreSupplier(@Nonnull final Function<String, KeyStore> keyStoreSupplier) {
    this.keyStoreSupplier = keyStoreSupplier;
  }

  /**
   * If a store configuration is used that has a store reference, and that reference points to a
   * {@link se.swedenconnect.security.credential.ReloadablePkiCredential}, a resolver function for getting a
   * {@link KeyStoreReloader} may be needed.
   *
   * @param keyStoreReloaderSupplier provides a {@link KeyStoreReloader} based on a key stores' registered ID
   */
  public void setKeyStoreReloaderSupplier(@Nonnull final Function<String, KeyStoreReloader> keyStoreReloaderSupplier) {
    this.keyStoreReloaderSupplier = keyStoreReloaderSupplier;
  }

  /**
   * Invokes
   * {@link PkiCredentialFactory#createCredential(PkiCredentialConfiguration, ConfigurationResourceLoader, Function,
   * Function)}.
   */
  @Override
  @Nonnull
  protected PkiCredential createInstance() throws Exception {
    return PkiCredentialFactory.createCredential(
        this.configuration, this.resourceLoader, this.keyStoreSupplier, this.keyStoreReloaderSupplier);
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public Class<?> getObjectType() {
    return PkiCredential.class;
  }

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() throws Exception {
    if (this.configuration.pem().isEmpty() && this.configuration.jks().isEmpty()) {
      throw new IllegalArgumentException("pem or jks must be supplied");
    }
    super.afterPropertiesSet();
  }

}
