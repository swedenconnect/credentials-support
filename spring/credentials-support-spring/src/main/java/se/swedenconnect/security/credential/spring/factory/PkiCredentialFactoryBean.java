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
import org.springframework.beans.factory.config.AbstractFactoryBean;
import org.springframework.core.io.DefaultResourceLoader;
import se.swedenconnect.security.credential.KeyStoreReloader;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.bundle.CredentialBundles;
import se.swedenconnect.security.credential.config.ConfigurationResourceLoader;
import se.swedenconnect.security.credential.config.PemCredentialConfiguration;
import se.swedenconnect.security.credential.config.PkiCredentialConfiguration;
import se.swedenconnect.security.credential.config.StoreCredentialConfiguration;
import se.swedenconnect.security.credential.factory.PkiCredentialFactory;
import se.swedenconnect.security.credential.spring.config.SpringConfigurationResourceLoader;

import java.security.KeyStore;
import java.util.Objects;
import java.util.Optional;
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

  /** For loading credential and key stores references. */
  private CredentialBundles credentialBundles;

  /** For resolving references to registered credentials. */
  private Function<String, PkiCredential> credentialProvider;

  /** For loading stores from references. */
  private Function<String, KeyStore> keyStoreProvider;

  /** For loading reloader implementations from key store references. */
  private Function<String, KeyStoreReloader> keyStoreReloaderProvider;

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
   * Constructor accepting a {@link String} which is a reference to a registered {@link PkiCredential}.
   *
   * @param bundle bundle reference
   */
  public PkiCredentialFactoryBean(@Nonnull final String bundle) {
    this(new PkiCredentialConfiguration() {

      @Override
      public Optional<String> bundle() {
        return Optional.of(bundle);
      }

      @Override
      public Optional<StoreCredentialConfiguration> jks() {
        return Optional.empty();
      }

      @Override
      public Optional<PemCredentialConfiguration> pem() {
        return Optional.empty();
      }
    });
  }

  /**
   * Constructor aceepting a {@link StoreCredentialConfiguration}.
   *
   * @param configuration the configuration
   */
  public PkiCredentialFactoryBean(@Nonnull final StoreCredentialConfiguration configuration) {
    this(new PkiCredentialConfiguration() {
      @Override
      public Optional<String> bundle() {
        return Optional.empty();
      }

      @Override
      public Optional<StoreCredentialConfiguration> jks() {
        return Optional.of(configuration);
      }

      @Override
      public Optional<PemCredentialConfiguration> pem() {
        return Optional.empty();
      }
    });
  }

  /**
   * Constructor aceepting a {@link PemCredentialConfiguration}.
   *
   * @param configuration the configuration
   */
  public PkiCredentialFactoryBean(@Nonnull final PemCredentialConfiguration configuration) {
    this(new PkiCredentialConfiguration() {

      @Override
      public Optional<String> bundle() {
        return Optional.empty();
      }

      @Override
      public Optional<StoreCredentialConfiguration> jks() {
        return Optional.empty();
      }

      @Override
      public Optional<PemCredentialConfiguration> pem() {
        return Optional.ofNullable(configuration);
      }
    });
  }

  /**
   * Assigns the {@link CredentialBundles} bean for resolving references to credentials and key stores.
   * <p>
   * Also see {@link #setCredentialProvider(Function)} and {@link #setKeyStoreProvider(Function)}.
   * </p>
   *
   * @param credentialBundles the credential bundles bean
   */
  public void setCredentialBundles(@Nonnull final CredentialBundles credentialBundles) {
    this.credentialBundles = credentialBundles;
  }

  /**
   * If a configuration is used that has a credential reference, a credential provider is needed.
   * <p>
   * An alternative to assigned this function, is to assign a {@link CredentialBundles}, see
   * {@link #setCredentialBundles(CredentialBundles)}.
   * </p>
   *
   * @param credentialProvider provides a {@link PkiCredential} based on its registered ID
   */
  public void setCredentialProvider(@Nonnull final Function<String, PkiCredential> credentialProvider) {
    this.credentialProvider = credentialProvider;
  }

  /**
   * If a store configuration is used that has a store reference, a key store provider is needed.
   * <p>
   * An alternative to assigned this function, is to assign a {@link CredentialBundles}, see
   * {@link #setCredentialBundles(CredentialBundles)}.
   * </p>
   *
   * @param keyStoreProvider provides a {@link KeyStore} based on its registered ID
   */
  public void setKeyStoreProvider(@Nonnull final Function<String, KeyStore> keyStoreProvider) {
    this.keyStoreProvider = keyStoreProvider;
  }

  /**
   * If a store configuration is used that has a store reference, and that reference points to a
   * {@link se.swedenconnect.security.credential.ReloadablePkiCredential}, a resolver function for getting a
   * {@link KeyStoreReloader} may be needed.
   *
   * @param keyStoreReloaderProvider provides a {@link KeyStoreReloader} based on a key stores' registered ID
   */
  public void setKeyStoreReloaderProvider(@Nonnull final Function<String, KeyStoreReloader> keyStoreReloaderProvider) {
    this.keyStoreReloaderProvider = keyStoreReloaderProvider;
  }

  /**
   * Invokes
   * {@link PkiCredentialFactory#createCredential(PkiCredentialConfiguration, ConfigurationResourceLoader, Function,
   * Function, Function)}.
   */
  @Override
  @Nonnull
  protected PkiCredential createInstance() throws Exception {
    return PkiCredentialFactory.createCredential(
        this.configuration, this.resourceLoader,
        Optional.ofNullable(this.credentialProvider).orElseGet(() -> Optional.ofNullable(this.credentialBundles)
            .map(CredentialBundles::getCredentialProvider)
            .orElse(null)),
        Optional.ofNullable(this.keyStoreProvider).orElseGet(() -> Optional.ofNullable(this.credentialBundles)
            .map(CredentialBundles::getKeyStoreProvider)
            .orElse(null)),
        this.keyStoreReloaderProvider);
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
    if (this.configuration.bundle().isEmpty()
        && this.configuration.pem().isEmpty()
        && this.configuration.jks().isEmpty()) {
      throw new IllegalArgumentException("bundle, pem or jks must be supplied");
    }
    if (this.configuration.bundle().isPresent()) {
      if (this.credentialProvider == null && this.credentialBundles == null) {
        throw new IllegalArgumentException("credentialProvider or credentialBundles must be supplied");
      }
    }
    super.afterPropertiesSet();
  }

  /**
   * Returns the underlying configuration.
   *
   * @return the underlying configuration
   */
  protected PkiCredentialConfiguration getConfiguration() {
    return this.configuration;
  }

}
