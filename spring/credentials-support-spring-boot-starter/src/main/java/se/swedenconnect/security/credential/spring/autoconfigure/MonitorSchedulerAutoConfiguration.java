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

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.TaskScheduler;
import se.swedenconnect.security.credential.monitoring.CredentialMonitorBean;

import java.time.Duration;
import java.util.Optional;

/**
 * For configuring scheduling of credential monitors.
 * <p>
 * If the application has a {@link TaskScheduler} bean (for example since it uses {@code @EnableScheduling}), that
 * scheduler is used. Otherwise, a dedicated scheduler is created, so scheduling does not have to be enabled by the
 * application.
 * </p>
 *
 * @author Martin Lindström
 */
@ConditionalOnBean(CredentialMonitorBean.class)
@AutoConfiguration(after = SpringCredentialBundlesAutoConfiguration.class,
    afterName = "org.springframework.boot.autoconfigure.task.TaskSchedulingAutoConfiguration")
public class MonitorSchedulerAutoConfiguration {

  /** The default interval between credential tests. */
  private static final Duration DEFAULT_TEST_INTERVAL = Duration.ofMinutes(10);

  /**
   * Creates a {@link CredentialMonitorScheduler} that runs the monitor bean periodically.
   *
   * @param monitorBean the monitor bean
   * @param properties the configuration properties (holding the test interval)
   * @param taskScheduler the application's task scheduler, if there is exactly one
   * @return a {@link CredentialMonitorScheduler}
   */
  @ConditionalOnMissingBean(CredentialMonitorScheduler.class)
  @Bean
  CredentialMonitorScheduler credentialMonitorScheduler(final CredentialMonitorBean monitorBean,
      final SpringCredentialConfigurationProperties properties, final ObjectProvider<TaskScheduler> taskScheduler) {
    return new CredentialMonitorScheduler(monitorBean,
        Optional.ofNullable(properties.getMonitoring().getTestInterval()).orElse(DEFAULT_TEST_INTERVAL),
        taskScheduler.getIfUnique());
  }

}
