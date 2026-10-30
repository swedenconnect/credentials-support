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

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;
import se.swedenconnect.security.credential.monitoring.CredentialMonitorBean;

import java.time.Duration;

/**
 * Test cases for {@link MonitorSchedulerAutoConfiguration}.
 *
 * @author Martin Lindström
 */
class MonitorSchedulerAutoConfigurationTest {

  private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
      .withConfiguration(AutoConfigurations.of(MonitorSchedulerAutoConfiguration.class))
      .withBean(SpringCredentialConfigurationProperties.class, () -> {
        final SpringCredentialConfigurationProperties properties = new SpringCredentialConfigurationProperties();
        properties.afterPropertiesSet();
        properties.getMonitoring().setTestInterval(Duration.ofMillis(100));
        return properties;
      });

  @Test
  void testNoMonitorBean() {
    this.contextRunner.run(context -> Assertions.assertThat(context).doesNotHaveBean(CredentialMonitorScheduler.class));
  }

  @Test
  void testScheduledWithoutApplicationScheduler() {
    final CredentialMonitorBean monitorBean = Mockito.mock(CredentialMonitorBean.class);
    this.contextRunner
        .withBean(CredentialMonitorBean.class, () -> monitorBean)
        .run(context -> {
          Assertions.assertThat(context).hasSingleBean(CredentialMonitorScheduler.class);
          Assertions.assertThat(context.getBean(CredentialMonitorScheduler.class).isRunning()).isTrue();
          Mockito.verify(monitorBean, Mockito.timeout(2000).atLeast(2)).test();
        });
  }

  @Test
  void testScheduledWithApplicationScheduler() {
    final CredentialMonitorBean monitorBean = Mockito.mock(CredentialMonitorBean.class);
    final ThreadPoolTaskScheduler taskScheduler = new ThreadPoolTaskScheduler();
    taskScheduler.initialize();
    try {
      this.contextRunner
          .withBean(CredentialMonitorBean.class, () -> monitorBean)
          .withBean(TaskScheduler.class, () -> taskScheduler)
          .run(context -> {
            Assertions.assertThat(context).hasSingleBean(CredentialMonitorScheduler.class);
            Mockito.verify(monitorBean, Mockito.timeout(2000).atLeast(2)).test();
          });
    }
    finally {
      taskScheduler.shutdown();
    }
  }

}
