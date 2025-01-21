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
package se.swedenconnect.security.credential.spring.autoconfigure;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ResourceLoader;
import org.springframework.scheduling.annotation.EnableScheduling;
import se.swedenconnect.security.credential.ReloadablePkiCredential;
import se.swedenconnect.security.credential.bundle.ConfigurationCredentialBundleRegistrar;
import se.swedenconnect.security.credential.bundle.CredentialBundleRegistrar;
import se.swedenconnect.security.credential.bundle.CredentialBundleRegistry;
import se.swedenconnect.security.credential.bundle.CredentialBundles;
import se.swedenconnect.security.credential.bundle.DefaultCredentialBundleRegistry;
import se.swedenconnect.security.credential.config.ConfigurationResourceLoader;
import se.swedenconnect.security.credential.monitoring.CredentialMonitorBean;
import se.swedenconnect.security.credential.monitoring.DefaultCredentialMonitorBean;
import se.swedenconnect.security.credential.spring.actuator.CredentialMonitorHealthIndicator;
import se.swedenconnect.security.credential.spring.config.SpringConfigurationResourceLoader;
import se.swedenconnect.security.credential.spring.monitoring.CredentialMonitoringCallbacks;

import java.util.List;

/**
 * Autoconfiguration class for setting up credential bundles.
 *
 * @author Martin Lindström
 */
@AutoConfiguration
@EnableConfigurationProperties(SpringCredentialBundlesConfigurationProperties.class)
public class SpringCredentialBundlesAutoConfiguration {

  /** Configuration properties. */
  private final SpringCredentialBundlesConfigurationProperties properties;

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
      final SpringCredentialBundlesConfigurationProperties properties, final ResourceLoader resourceLoader) {
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
    return new ConfigurationCredentialBundleRegistrar(this.properties, configurationResourceLoader);
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
   * Creates a {@link CredentialMonitorBean}.
   *
   * @param credentialBundles the bundles holding all credentials
   * @param eventPublisher for publishing events
   * @return a {@link DefaultCredentialMonitorBean}
   */
  @ConditionalOnMissingBean(CredentialMonitorBean.class)
  @ConditionalOnProperty(
      prefix = "credential.bundles.monitoring", name = "enabled", havingValue = "true", matchIfMissing = false)
  @Bean
  DefaultCredentialMonitorBean credentialMonitorBean(
      final CredentialBundles credentialBundles, final ApplicationEventPublisher eventPublisher) {

    final List<String> ids = credentialBundles.getRegisteredCredentials();
    final List<ReloadablePkiCredential> credentials = ids.stream()
        .map(credentialBundles::getCredential)
        .filter(ReloadablePkiCredential.class::isInstance)
        .map(ReloadablePkiCredential.class::cast)
        .filter(c -> c.getTestFunction() != null)
        .toList();

    final CredentialMonitoringCallbacks callbacks = new CredentialMonitoringCallbacks(eventPublisher);

    final DefaultCredentialMonitorBean monitorBean = new DefaultCredentialMonitorBean(credentials);
    monitorBean.setTestSuccessCallback(callbacks.getTestSuccessCallback());
    monitorBean.setFailureCallback(callbacks.getTestFailureCallback());
    monitorBean.setReloadSuccessCallback(callbacks.getReloadSuccessCallback());
    monitorBean.setReloadFailureCallback(callbacks.getReloadFailureCallback());

    this.createdMonitorWithEvents = true;
    return monitorBean;
  }

  /**
   * Creates a {@link CredentialMonitorHealthIndicator} component. If we have defined a
   * {@link DefaultCredentialMonitorBean} that signals events for monitoring results, the indicator is set up in
   * "passive" mode listening for events, and if not, it sets up its own monitor.
   *
   * @param credentialBundles credential bundles (needed for active mode)
   * @return a {@link CredentialMonitorHealthIndicator} bean
   */
  @ConditionalOnClass(HealthIndicator.class)
  @ConditionalOnMissingBean(CredentialMonitorHealthIndicator.class)
  @ConditionalOnProperty(
      prefix = "credential.bundles.monitoring", name = "health-endpoint-enabled", havingValue = "true", matchIfMissing = false)
  @Bean("credential-monitor")
  CredentialMonitorHealthIndicator credentialMonitor(final CredentialBundles credentialBundles) {

    if (this.createdMonitorWithEvents) {
      return new CredentialMonitorHealthIndicator();
    }
    else {
      final List<String> ids = credentialBundles.getRegisteredCredentials();
      final List<ReloadablePkiCredential> credentials = ids.stream()
          .map(credentialBundles::getCredential)
          .filter(ReloadablePkiCredential.class::isInstance)
          .map(ReloadablePkiCredential.class::cast)
          .filter(c -> c.getTestFunction() != null)
          .toList();
      return new CredentialMonitorHealthIndicator(credentials);
    }
  }

}
