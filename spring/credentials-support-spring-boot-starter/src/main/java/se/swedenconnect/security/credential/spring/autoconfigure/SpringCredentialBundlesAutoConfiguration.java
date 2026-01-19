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
package se.swedenconnect.security.credential.spring.autoconfigure;

import jakarta.annotation.Nullable;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.PkiCredentialCollection;
import se.swedenconnect.security.credential.ReloadablePkiCredential;
import se.swedenconnect.security.credential.bundle.ConfigurationCredentialBundleRegistrar;
import se.swedenconnect.security.credential.bundle.CredentialBundleRegistrar;
import se.swedenconnect.security.credential.bundle.CredentialBundleRegistry;
import se.swedenconnect.security.credential.bundle.CredentialBundles;
import se.swedenconnect.security.credential.bundle.DefaultCredentialBundleRegistry;
import se.swedenconnect.security.credential.config.ConfigurationResourceLoader;
import se.swedenconnect.security.credential.config.PkiCredentialConfiguration;
import se.swedenconnect.security.credential.factory.PkiCredentialFactory;
import se.swedenconnect.security.credential.monitoring.CredentialMonitorBean;
import se.swedenconnect.security.credential.monitoring.DefaultCredentialMonitorBean;
import se.swedenconnect.security.credential.spring.actuator.CredentialMonitorHealthIndicator;
import se.swedenconnect.security.credential.spring.config.SpringConfigurationResourceLoader;
import se.swedenconnect.security.credential.spring.monitoring.CredentialMonitoringCallbacks;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Autoconfiguration class for setting up credential bundles, collections and monitoring.
 *
 * @author Martin Lindström
 */
@AutoConfiguration
@EnableConfigurationProperties(SpringCredentialConfigurationProperties.class)
public class SpringCredentialBundlesAutoConfiguration {

  /** Configuration properties. */
  private final SpringCredentialConfigurationProperties properties;

  /** Spring resource loader. */
  private final ResourceLoader resourceLoader;

  /** If we set up a {@link DefaultCredentialMonitorBean}, this property is assigned. */
  private boolean createdMonitorWithEvents = false;

  /**
   * Constructor.
   *
   * @param properties configuration properties
   */
  public SpringCredentialBundlesAutoConfiguration(
      final SpringCredentialConfigurationProperties properties, final ResourceLoader resourceLoader) {
    this.properties = properties;
    this.resourceLoader = resourceLoader;
  }

  /**
   * Sets up a {@link ConfigurationResourceLoader} bean.
   *
   * @return a {@link ConfigurationResourceLoader} bean
   */
  @ConditionalOnMissingBean
  @Bean
  ConfigurationResourceLoader configurationResourceLoader() {
    return new SpringConfigurationResourceLoader(this.resourceLoader);
  }

  /**
   * Bean responsible for registering credentials and key stores.
   *
   * @param configurationResourceLoader a {@link ConfigurationResourceLoader} bean
   * @return {@link CredentialBundleRegistrar} bean
   */
  @Bean
  CredentialBundleRegistrar credentialsBundlesRegistrar(final ConfigurationResourceLoader configurationResourceLoader) {
    return new ConfigurationCredentialBundleRegistrar(this.properties.getBundles(), configurationResourceLoader);
  }

  /**
   * Creates a bean that implements both the {@link CredentialBundles} and the {@link CredentialBundleRegistry}
   * interfaces.
   *
   * @param registrars credential registrars
   * @return a {@link DefaultCredentialBundleRegistry} bean
   */
  @Bean
  @ConditionalOnMissingBean({ CredentialBundles.class, CredentialBundleRegistry.class })
  DefaultCredentialBundleRegistry credentialBundlesRegistry(
      final ObjectProvider<CredentialBundleRegistrar> registrars) {
    final DefaultCredentialBundleRegistry registry = new DefaultCredentialBundleRegistry();
    registrars.orderedStream().forEach((registrar) -> registrar.register(registry));
    return registry;
  }

  /**
   * Creates a {@link PkiCredentialFactory} bean.
   *
   * @param credentialBundles the credential bundle bean
   * @param configurationResourceLoader the resource loader
   * @return a {@link PkiCredentialFactory}
   */
  @Bean
  @ConditionalOnMissingBean
  PkiCredentialFactory pkiCredentialFactory(final CredentialBundles credentialBundles,
      final ConfigurationResourceLoader configurationResourceLoader) {
    return new PkiCredentialFactory(credentialBundles, configurationResourceLoader, true);
  }

  /**
   * Creates a {@link PkiCredentialCollection} bean named {@code credential-collection}.
   *
   * @param pkiCredentialFactory the credential factory
   * @return a {@link PkiCredentialCollection} bean
   * @throws Exception for errors creating the credentials
   */
  @Bean("credential-collection")
  PkiCredentialCollection pkiCredentialCollection(final PkiCredentialFactory pkiCredentialFactory) throws Exception {
    return this.properties.getCollection().credentials().isPresent()
        ? pkiCredentialFactory.createCredentialCollection(this.properties.getCollection())
        : new PkiCredentialCollection(Collections.emptyList());
  }

  /**
   * Creates a {@link CredentialMonitorBean}.
   *
   * @param credentialBundles the bundles holding credentials
   * @param collection a collection that also holds credentials
   * @param eventPublisher for publishing events
   * @return a {@link DefaultCredentialMonitorBean}
   */
  @ConditionalOnMissingBean(CredentialMonitorBean.class)
  @ConditionalOnExpression(
      "T(java.lang.Boolean).parseBoolean('${credential.bundles.monitoring.enabled:false}') " +
          "or T(java.lang.Boolean).parseBoolean('${credential.monitoring.enabled:false}')")
  @Bean
  DefaultCredentialMonitorBean credentialMonitorBean(final CredentialBundles credentialBundles,
      @Qualifier("credential-collection") final PkiCredentialCollection collection,
      final ApplicationEventPublisher eventPublisher) {

    final List<ReloadablePkiCredential> credentials = getCredentialsForMonitoring(
        credentialBundles, collection, this.properties);
    final CredentialMonitoringCallbacks callbacks = new CredentialMonitoringCallbacks(eventPublisher);

    final DefaultCredentialMonitorBean monitorBean = new DefaultCredentialMonitorBean(credentials);
    monitorBean.setTestSuccessCallback(callbacks.getTestSuccessCallback());
    monitorBean.setFailureCallback(callbacks.getTestFailureCallback());
    monitorBean.setReloadSuccessCallback(callbacks.getReloadSuccessCallback());
    monitorBean.setReloadFailureCallback(callbacks.getReloadFailureCallback());

    this.createdMonitorWithEvents = true;
    return monitorBean;
  }

  static List<ReloadablePkiCredential> getCredentialsForMonitoring(
      final CredentialBundles credentialBundles, final PkiCredentialCollection collection,
      final SpringCredentialConfigurationProperties properties) {
    final List<String> ids = credentialBundles.getRegisteredCredentials();
    final List<ReloadablePkiCredential> credentials = ids.stream()
        .map(credentialBundles::getCredential)
        .filter(ReloadablePkiCredential.class::isInstance)
        .map(ReloadablePkiCredential.class::cast)
        .filter(c -> c.getTestFunction() != null)
        .collect(Collectors.toList());

    final List<PkiCredential> collectionCredentials = Optional.ofNullable(collection.getCredentials())
        .orElseGet(Collections::emptyList);
    for (int i = 0; i < properties.getCollection().getCredentials().size(); i++) {
      final PkiCredentialConfiguration conf = properties.getCollection().getCredentials().get(i);
      // Bundles are already handled above. We only check the other credentials from the collection.
      if (conf.bundle().isEmpty()) {
        if (collectionCredentials.get(i) instanceof final ReloadablePkiCredential reloadablePkiCredential) {
          if (reloadablePkiCredential.getTestFunction() != null) {
            credentials.add(reloadablePkiCredential);
          }
        }
      }
    }
    return credentials;
  }

  /**
   * Configuration for the optional actuator.
   */
  @Configuration
  @ConditionalOnClass(HealthIndicator.class)
  @ConditionalOnExpression(
      "T(java.lang.Boolean).parseBoolean('${credential.bundles.monitoring.health-endpoint-enabled:false}') " +
          "or T(java.lang.Boolean).parseBoolean('${credential.monitoring.health-endpoint-enabled:false}')")
  public static class ActuatorHealthConfiguration {

    private final SpringCredentialConfigurationProperties properties;

    /**
     * Constructor.
     *
     * @param properties the {@link SpringCredentialConfigurationProperties}
     */
    public ActuatorHealthConfiguration(final SpringCredentialConfigurationProperties properties) {
      this.properties = properties;
    }

    /**
     * Creates a {@link CredentialMonitorHealthIndicator} component. If we have defined a
     * {@link DefaultCredentialMonitorBean} that signals events for monitoring results, the indicator is set up in
     * "passive" mode listening for events, and if not, it sets up its own monitor.
     *
     * @param credentialBundles credential bundles (needed for active mode)
     * @param collection a collection that also holds credentials
     * @param defaultCredentialMonitorBean optional monitor bean that may be used
     * @return a {@link CredentialMonitorHealthIndicator} bean
     */
    @ConditionalOnMissingBean(CredentialMonitorHealthIndicator.class)
    @Bean("credential-monitor")
    CredentialMonitorHealthIndicator credentialMonitor(final CredentialBundles credentialBundles,
        @Qualifier("credential-collection") final PkiCredentialCollection collection,
        @Autowired(required = false) @Nullable final DefaultCredentialMonitorBean defaultCredentialMonitorBean) {

      return defaultCredentialMonitorBean != null
          ? new CredentialMonitorHealthIndicator()
          : new CredentialMonitorHealthIndicator(getCredentialsForMonitoring(
              credentialBundles, collection, this.properties));
    }

  }

}
