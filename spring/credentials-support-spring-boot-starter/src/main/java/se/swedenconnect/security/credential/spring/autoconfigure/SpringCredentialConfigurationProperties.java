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

import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import se.swedenconnect.security.credential.config.properties.CredentialBundlesConfigurationProperties;
import se.swedenconnect.security.credential.config.properties.PkiCredentialCollectionConfigurationProperties;

import java.time.Duration;
import java.util.Collections;

/**
 * Configuration properties for credential bundles, collections and monitoring.
 *
 * @author Martin Lindström
 */
@ConfigurationProperties("credential")
public class SpringCredentialConfigurationProperties implements InitializingBean {

  /**
   * Configuration properties for bundles of credentials and key stores.
   */
  @NestedConfigurationProperty
  private final CredentialBundlesConfigurationProperties bundles = new CredentialBundlesConfigurationProperties();

  /**
   * Configuration for setting up a PkiCredentialCollection bean.
   */
  @NestedConfigurationProperty
  private final PkiCredentialCollectionConfigurationProperties collection =
      new PkiCredentialCollectionConfigurationProperties();

  /**
   * Configuration for monitoring credentials.
   */
  @NestedConfigurationProperty
  private MonitoringProperties monitoring;

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() {
    if (this.collection.credentials().isEmpty()) {
      this.collection.setCredentials(Collections.emptyList());
    }
    if (this.monitoring == null) {
      this.monitoring = new MonitoringProperties();
    }
  }

  /**
   * For monitoring.
   */
  public static class MonitoringProperties {

    /**
     * Whether credential monitoring is enabled.
     */
    private boolean enabled;

    /**
     * The interval between tests of credentials. The default is 10 minutes.
     */
    private Duration testInterval = Duration.ofMinutes(10);

    /**
     * Whether a HealthEndpoint for monitoring should be set up.
     */
    private boolean healthEndpointEnabled;

    /**
     * Tells whether credential monitoring is enabled.
     *
     * @return whether credential monitoring is enabled
     */
    public boolean isEnabled() {
      return this.enabled;
    }

    /**
     * Assigns whether credential monitoring is enabled.
     *
     * @param enabled whether credential monitoring is enabled
     */
    public void setEnabled(final boolean enabled) {
      this.enabled = enabled;
    }

    /**
     * Gets the interval between tests of credentials.
     *
     * @return the interval between tests of credentials
     */
    public Duration getTestInterval() {
      return this.testInterval;
    }

    /**
     * Assigns the interval between tests of credentials.
     *
     * @param testInterval the interval between tests of credentials
     */
    public void setTestInterval(final Duration testInterval) {
      this.testInterval = testInterval;
    }

    /**
     * Tells whether a HealthEndpoint for monitoring should be set up.
     *
     * @return whether a HealthEndpoint for monitoring should be set up
     */
    public boolean isHealthEndpointEnabled() {
      return this.healthEndpointEnabled;
    }

    /**
     * Assigns whether a HealthEndpoint for monitoring should be set up.
     *
     * @param healthEndpointEnabled whether a HealthEndpoint for monitoring should be set up
     */
    public void setHealthEndpointEnabled(final boolean healthEndpointEnabled) {
      this.healthEndpointEnabled = healthEndpointEnabled;
    }

  }

  /**
   * Gets the configuration properties for bundles of credentials and key stores.
   *
   * @return the configuration properties for bundles of credentials and key stores
   */
  public CredentialBundlesConfigurationProperties getBundles() {
    return this.bundles;
  }

  /**
   * Gets the configuration for setting up a PkiCredentialCollection bean.
   *
   * @return the configuration for setting up a PkiCredentialCollection bean
   */
  public PkiCredentialCollectionConfigurationProperties getCollection() {
    return this.collection;
  }

  /**
   * Gets the configuration for monitoring credentials.
   *
   * @return the configuration for monitoring credentials
   */
  public MonitoringProperties getMonitoring() {
    return this.monitoring;
  }

  /**
   * Assigns the configuration for monitoring credentials.
   *
   * @param monitoring the configuration for monitoring credentials
   */
  public void setMonitoring(final MonitoringProperties monitoring) {
    this.monitoring = monitoring;
  }

}
