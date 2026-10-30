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

import lombok.Getter;
import lombok.Setter;
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
  @Getter
  @NestedConfigurationProperty
  private final CredentialBundlesConfigurationProperties bundles = new CredentialBundlesConfigurationProperties();

  /**
   * Configuration for setting up a PkiCredentialCollection bean.
   */
  @Getter
  @NestedConfigurationProperty
  private final PkiCredentialCollectionConfigurationProperties collection =
      new PkiCredentialCollectionConfigurationProperties();

  /**
   * Configuration for monitoring credentials.
   */
  @Getter
  @Setter
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
    @Getter
    @Setter
    private boolean enabled;

    /**
     * The interval between tests of credentials. The default is 10 minutes.
     */
    @Getter
    @Setter
    private Duration testInterval = Duration.ofMinutes(10);

    /**
     * Whether a HealthEndpoint for monitoring should be set up.
     */
    @Getter
    @Setter
    private boolean healthEndpointEnabled;

  }

}
