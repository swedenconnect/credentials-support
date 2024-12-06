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
package se.swedenconnect.security.credential.spring.actuator;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.annotation.Nonnull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.actuate.health.Status;
import org.springframework.context.event.EventListener;
import se.swedenconnect.security.credential.ReloadablePkiCredential;
import se.swedenconnect.security.credential.monitoring.DefaultCredentialMonitorBean;
import se.swedenconnect.security.credential.spring.monitoring.events.FailedCredentialReloadEvent;
import se.swedenconnect.security.credential.spring.monitoring.events.FailedCredentialTestEvent;
import se.swedenconnect.security.credential.spring.monitoring.events.SuccessfulCredentialReloadEvent;
import se.swedenconnect.security.credential.spring.monitoring.events.SuccessfulCredentialTestEvent;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A {@link HealthIndicator} for monitoring credentials.
 * <p>
 * The indicator can either work in a passive mode where it listens to monitor events (use
 * {@link #CredentialMonitorHealthIndicator()}), or in "active" mode where the indicator sets up a
 * {@link se.swedenconnect.security.credential.monitoring.CredentialMonitorBean CredentialMonitorBean} (use
 * {@link #CredentialMonitorHealthIndicator(List)}).
 * </p>
 *
 * @author Martin Lindström
 */
public class CredentialMonitorHealthIndicator implements HealthIndicator {

  /** Custom health status for warnings. */
  public static final Status WARNING = new Status("WARNING");

  /** Logger instance. */
  private static final Logger log = LoggerFactory.getLogger(CredentialMonitorHealthIndicator.class);

  /** The current monitor status. */
  private final Map<String, MonitorStatus> status = new ConcurrentHashMap<>();

  /** The monitor bean. */
  private final DefaultCredentialMonitorBean monitor;

  /**
   * Credential assuming that monitor events will be published.
   */
  public CredentialMonitorHealthIndicator() {
    this.monitor = null;
  }

  /**
   * Constructor setting up a monitor.
   *
   * @param credentials the credentials to monitor
   */
  public CredentialMonitorHealthIndicator(@Nonnull final List<ReloadablePkiCredential> credentials) {
    this.monitor = new DefaultCredentialMonitorBean(
        Objects.requireNonNull(credentials, "credentials must not be null"));
    this.monitor.setTestSuccessCallback(
        c -> this.onSuccessfulCredentialTestEvent(new SuccessfulCredentialTestEvent(c.getName())));
    this.monitor.setFailureCallback((cred, ex) -> {
      this.onFailedCredentialTestEvent(
          new FailedCredentialTestEvent(cred.getName(), ex.getMessage(), ex.getClass().getName()));
      return true;
    });
    this.monitor.setReloadSuccessCallback(
        c -> this.onSuccessfulCredentialReloadEvent(new SuccessfulCredentialReloadEvent(c.getName())));
    this.monitor.setReloadFailureCallback((cred, ex) -> this.onFailedCredentialReloadEvent(
        new FailedCredentialReloadEvent(cred.getName(), ex.getMessage(), ex.getClass().getName())));
  }

  /**
   * Tests all configured credentials, and performs reload on those that fail tests.
   */
  @Override
  public Health health() {

    if (this.monitor != null) {
      log.debug("Health indicator starting test of credentials ...");
      this.monitor.test();
      log.debug("Health indicator finished testing/reloading credentials");
    }

    // Put together result ...
    //
    if (this.status.isEmpty()) {
      return Health.up().build();
    }

    Status status = Status.UP;
    for (final MonitorStatus monitorStatus : this.status.values()) {
      if (Status.DOWN.equals(monitorStatus.getStatus())) {
        status = Status.DOWN;
        break;
      }
      else if (WARNING.equals(monitorStatus.getStatus())) {
        status = WARNING;
      }
    }
    final Health.Builder builder = new Health.Builder();
    return builder
        .status(status)
        .withDetails(Map.of("credentials", this.status.values().stream().toList()))
        .build();
  }

  @EventListener
  public void onSuccessfulCredentialTestEvent(final SuccessfulCredentialTestEvent event) {
    Optional.ofNullable(this.status.get(event.getCredentialName()))
        .ifPresentOrElse(s -> s.setTestResult(MonitorStatus.OK),
            () -> this.status.put(event.getCredentialName(), MonitorStatus.builder()
                .credentialName(event.getCredentialName())
                .testResult(MonitorStatus.OK)
                .build()));
  }

  @EventListener
  public void onFailedCredentialTestEvent(final FailedCredentialTestEvent event) {
    Optional.ofNullable(this.status.get(event.getCredentialName()))
        .ifPresentOrElse(s -> {
              s.setTestResult(MonitorStatus.ERROR);
              s.setTestError(event.getError());
              s.setTestException(event.getException());
            },
            () -> this.status.put(event.getCredentialName(), MonitorStatus.builder()
                .credentialName(event.getCredentialName())
                .testResult(MonitorStatus.ERROR)
                .testError(event.getError())
                .testException(event.getException())
                .build()));

  }

  @EventListener
  public void onSuccessfulCredentialReloadEvent(final SuccessfulCredentialReloadEvent event) {
    Optional.ofNullable(this.status.get(event.getCredentialName()))
        .ifPresentOrElse(s -> s.setReloadResult(MonitorStatus.OK),
            () -> this.status.put(event.getCredentialName(), MonitorStatus.builder()
                .credentialName(event.getCredentialName())
                .testResult(MonitorStatus.ERROR)
                .testError("Unknown")
                .reloadResult(MonitorStatus.OK)
                .build()));
  }

  @EventListener
  public void onFailedCredentialReloadEvent(final FailedCredentialReloadEvent event) {
    Optional.ofNullable(this.status.get(event.getCredentialName()))
        .ifPresentOrElse(s -> {
              s.setReloadResult(MonitorStatus.ERROR);
              s.setReloadError(event.getError());
              s.setReloadException(event.getException());
            },
            () -> this.status.put(event.getCredentialName(), MonitorStatus.builder()
                .credentialName(event.getCredentialName())
                .testResult(MonitorStatus.ERROR)
                .testError("Unknown")
                .reloadResult(MonitorStatus.ERROR)
                .reloadError(event.getError())
                .reloadException(event.getException())
                .build()));
  }

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  @Builder
  @JsonInclude(JsonInclude.Include.NON_EMPTY)
  public static class MonitorStatus {

    public static final String OK = "success";
    public static final String ERROR = "failure";

    @JsonProperty("credential-name")
    private String credentialName;

    @JsonProperty("test-result")
    private String testResult;

    @JsonProperty("test-error")
    private String testError;

    @JsonProperty("test-exception")
    private String testException;

    @JsonProperty("reload-result")
    private String reloadResult;

    @JsonProperty("reload-error")
    private String reloadError;

    @JsonProperty("reload-exception")
    private String reloadException;

    @JsonIgnore
    public Status getStatus() {
      if (OK.equals(this.testResult)) {
        return Status.UP;
      }
      if (ERROR.equals(this.reloadResult)) {
        return Status.DOWN;
      }
      return WARNING;
    }

  }

}
