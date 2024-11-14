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
package se.swedenconnect.security.credential.spring.autoconfigure;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import se.swedenconnect.security.credential.config.properties.CredentialBundlesConfigurationProperties;

import java.time.Duration;

/**
 * Configuration properties for bundles of credentials and key stores.
 *
 * @author Martin Lindström
 * @see CredentialBundlesConfigurationProperties
 */
@ConfigurationProperties("credential.bundles")
public class SpringCredentialBundlesConfigurationProperties extends CredentialBundlesConfigurationProperties {

  /**
   * Credential health endpoint monitoring.
   */
  @Getter
  @Setter
  private boolean healthEndpointEnabled;

  /**
   * Configuration for monitoring credentials.
   */
  @Getter
  private final MonitoringProperties monitoring = new MonitoringProperties();

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
     * Whether a HealthEndpoint for monitoring should be set up. Note that overall monitoring must be enabled.
     */
    @Getter
    @Setter
    private boolean healthEndpointEnabled;

  }

}
