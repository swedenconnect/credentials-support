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

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.SmartLifecycle;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;
import se.swedenconnect.security.credential.monitoring.CredentialMonitorBean;
import se.swedenconnect.security.credential.monitoring.CredentialMonitorTask;

import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.ScheduledFuture;

/**
 * Schedules a {@link CredentialMonitorBean} to run periodically. If a {@link TaskScheduler} is supplied, it is used,
 * otherwise a dedicated single-thread scheduler is created (and shut down when the application stops). This means that
 * the application does not need to enable Spring scheduling for credential monitoring to work.
 *
 * @author Martin Lindström
 */
public class CredentialMonitorScheduler implements SmartLifecycle {

  /** Logger instance. */
  private static final Logger log = LoggerFactory.getLogger(CredentialMonitorScheduler.class);

  /** The monitor to run. */
  private final CredentialMonitorBean monitorBean;

  /** The delay between the end of one test run and the start of the next. */
  private final Duration testInterval;

  /** The scheduler supplied by the application, may be {@code null}. */
  private final TaskScheduler applicationScheduler;

  /** The scheduler created by this instance if no scheduler was supplied. */
  private ThreadPoolTaskScheduler ownScheduler;

  /** The scheduled monitor task. */
  private ScheduledFuture<?> scheduledTask;

  /**
   * Constructor.
   *
   * @param monitorBean the monitor to run
   * @param testInterval the delay between test runs
   * @param taskScheduler the scheduler to use, or {@code null} for a dedicated scheduler
   */
  public CredentialMonitorScheduler(@Nonnull final CredentialMonitorBean monitorBean,
      @Nonnull final Duration testInterval, @Nullable final TaskScheduler taskScheduler) {
    this.monitorBean = Objects.requireNonNull(monitorBean, "monitorBean must not be null");
    this.testInterval = Objects.requireNonNull(testInterval, "testInterval must not be null");
    this.applicationScheduler = taskScheduler;
  }

  /**
   * Schedules the monitor task.
   */
  @Override
  public synchronized void start() {
    if (this.scheduledTask != null) {
      return;
    }
    TaskScheduler scheduler = this.applicationScheduler;
    if (scheduler == null) {
      this.ownScheduler = new ThreadPoolTaskScheduler();
      this.ownScheduler.setPoolSize(1);
      this.ownScheduler.setThreadNamePrefix("credential-monitor-");
      this.ownScheduler.initialize();
      scheduler = this.ownScheduler;
    }
    this.scheduledTask =
        scheduler.scheduleWithFixedDelay(new CredentialMonitorTask(this.monitorBean), this.testInterval);
    log.info("Credential monitoring scheduled with interval {}{}", this.testInterval,
        this.ownScheduler != null ? " (using dedicated scheduler)" : "");
  }

  /**
   * Cancels the monitor task, and shuts down the dedicated scheduler if one was created.
   */
  @Override
  public synchronized void stop() {
    if (this.scheduledTask != null) {
      this.scheduledTask.cancel(false);
      this.scheduledTask = null;
    }
    if (this.ownScheduler != null) {
      this.ownScheduler.shutdown();
      this.ownScheduler = null;
    }
  }

  /** {@inheritDoc} */
  @Override
  public synchronized boolean isRunning() {
    return this.scheduledTask != null;
  }

}
