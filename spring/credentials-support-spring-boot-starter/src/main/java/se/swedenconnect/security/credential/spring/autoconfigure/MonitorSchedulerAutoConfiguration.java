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

import jakarta.annotation.Nonnull;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;
import se.swedenconnect.security.credential.monitoring.CredentialMonitorBean;
import se.swedenconnect.security.credential.monitoring.CredentialMonitorTask;

import java.time.Duration;
import java.util.Optional;

/**
 * For configuring scheduling of credential monitors.
 *
 * @author Martin Lindström
 */
@ConditionalOnBean({ CredentialMonitorBean.class, TaskScheduler.class })
@ConditionalOnProperty(
    prefix = "credential.bundles.monitoring", name = "enabled", havingValue = "true", matchIfMissing = false)
@AutoConfiguration
@AutoConfigureAfter({ SpringCredentialBundlesAutoConfiguration.class })
public class MonitorSchedulerAutoConfiguration implements SchedulingConfigurer {

  private final TaskScheduler taskScheduler;
  private final CredentialMonitorBean monitorBean;
  private final SpringCredentialBundlesConfigurationProperties properties;

  public MonitorSchedulerAutoConfiguration(final TaskScheduler taskScheduler, final CredentialMonitorBean monitorBean,
      final SpringCredentialBundlesConfigurationProperties properties) {
    this.taskScheduler = taskScheduler;
    this.monitorBean = monitorBean;
    this.properties = properties;
  }

  @Override
  public void configureTasks(@Nonnull final ScheduledTaskRegistrar taskRegistrar) {
    taskRegistrar.setScheduler(this.taskScheduler);
    taskRegistrar.addFixedDelayTask(new CredentialMonitorTask(this.monitorBean),
        Optional.ofNullable(this.properties.getMonitoring().getTestInterval())
            .orElseGet(() -> Duration.ofMinutes(10)));
  }

}
