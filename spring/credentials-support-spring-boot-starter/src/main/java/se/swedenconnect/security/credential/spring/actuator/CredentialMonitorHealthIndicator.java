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
package se.swedenconnect.security.credential.spring.actuator;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.annotation.Nonnull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.boot.health.contributor.Status;
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
        .ifPresentOrElse(s -> {
              // The credential works again, so details from an earlier failure are cleared ...
              s.setTestResult(MonitorStatus.OK);
              s.setTestError(null);
              s.setTestException(null);
              s.setReloadResult(null);
              s.setReloadError(null);
              s.setReloadException(null);
            },
            () -> this.status.put(event.getCredentialName(), MonitorStatus.builder()
                .credentialName(event.getCredentialName())
                .testResult(MonitorStatus.OK)
                .build()));
  }

  @EventListener
  public void onFailedCredentialTestEvent(final FailedCredentialTestEvent event) {
    Optional.ofNullable(this.status.get(event.getCredentialName()))
        .ifPresentOrElse(s -> {
              // A new failure, so the result of an earlier reload is cleared ...
              s.setTestResult(MonitorStatus.ERROR);
              s.setTestError(event.getError());
              s.setTestException(event.getException());
              s.setReloadResult(null);
              s.setReloadError(null);
              s.setReloadException(null);
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
        .ifPresentOrElse(s -> {
              s.setReloadResult(MonitorStatus.OK);
              s.setReloadError(null);
              s.setReloadException(null);
            },
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

  /**
   * Status for a monitored credential.
   */
  @JsonInclude(JsonInclude.Include.NON_EMPTY)
  public static class MonitorStatus {

    /** Result value for a successful test or reload. */
    public static final String OK = "success";

    /** Result value for a failed test or reload. */
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

    /**
     * Default constructor.
     */
    public MonitorStatus() {
    }

    /**
     * Constructor assigning all fields.
     *
     * @param credentialName the credential name
     * @param testResult the test result
     * @param testError the test error message
     * @param testException the test exception class name
     * @param reloadResult the reload result
     * @param reloadError the reload error message
     * @param reloadException the reload exception class name
     */
    public MonitorStatus(final String credentialName, final String testResult, final String testError,
        final String testException, final String reloadResult, final String reloadError,
        final String reloadException) {
      this.credentialName = credentialName;
      this.testResult = testResult;
      this.testError = testError;
      this.testException = testException;
      this.reloadResult = reloadResult;
      this.reloadError = reloadError;
      this.reloadException = reloadException;
    }

    /**
     * Creates a builder for {@link MonitorStatus} objects.
     *
     * @return a builder
     */
    public static MonitorStatusBuilder builder() {
      return new MonitorStatusBuilder();
    }

    /**
     * Gets the credential name.
     *
     * @return the credential name
     */
    public String getCredentialName() {
      return this.credentialName;
    }

    /**
     * Assigns the credential name.
     *
     * @param credentialName the credential name
     */
    public void setCredentialName(final String credentialName) {
      this.credentialName = credentialName;
    }

    /**
     * Gets the test result.
     *
     * @return the test result
     */
    public String getTestResult() {
      return this.testResult;
    }

    /**
     * Assigns the test result.
     *
     * @param testResult the test result
     */
    public void setTestResult(final String testResult) {
      this.testResult = testResult;
    }

    /**
     * Gets the test error message.
     *
     * @return the test error message
     */
    public String getTestError() {
      return this.testError;
    }

    /**
     * Assigns the test error message.
     *
     * @param testError the test error message
     */
    public void setTestError(final String testError) {
      this.testError = testError;
    }

    /**
     * Gets the test exception class name.
     *
     * @return the test exception class name
     */
    public String getTestException() {
      return this.testException;
    }

    /**
     * Assigns the test exception class name.
     *
     * @param testException the test exception class name
     */
    public void setTestException(final String testException) {
      this.testException = testException;
    }

    /**
     * Gets the reload result.
     *
     * @return the reload result
     */
    public String getReloadResult() {
      return this.reloadResult;
    }

    /**
     * Assigns the reload result.
     *
     * @param reloadResult the reload result
     */
    public void setReloadResult(final String reloadResult) {
      this.reloadResult = reloadResult;
    }

    /**
     * Gets the reload error message.
     *
     * @return the reload error message
     */
    public String getReloadError() {
      return this.reloadError;
    }

    /**
     * Assigns the reload error message.
     *
     * @param reloadError the reload error message
     */
    public void setReloadError(final String reloadError) {
      this.reloadError = reloadError;
    }

    /**
     * Gets the reload exception class name.
     *
     * @return the reload exception class name
     */
    public String getReloadException() {
      return this.reloadException;
    }

    /**
     * Assigns the reload exception class name.
     *
     * @param reloadException the reload exception class name
     */
    public void setReloadException(final String reloadException) {
      this.reloadException = reloadException;
    }

    /**
     * Gets the overall health status for the credential.
     *
     * @return the status
     */
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

    /** {@inheritDoc} */
    @Override
    public boolean equals(final Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || this.getClass() != o.getClass()) {
        return false;
      }
      final MonitorStatus that = (MonitorStatus) o;
      return Objects.equals(this.credentialName, that.credentialName)
          && Objects.equals(this.testResult, that.testResult)
          && Objects.equals(this.testError, that.testError)
          && Objects.equals(this.testException, that.testException)
          && Objects.equals(this.reloadResult, that.reloadResult)
          && Objects.equals(this.reloadError, that.reloadError)
          && Objects.equals(this.reloadException, that.reloadException);
    }

    /** {@inheritDoc} */
    @Override
    public int hashCode() {
      return Objects.hash(this.credentialName, this.testResult, this.testError, this.testException,
          this.reloadResult, this.reloadError, this.reloadException);
    }

    /** {@inheritDoc} */
    @Override
    public String toString() {
      return "MonitorStatus(credentialName=" + this.credentialName + ", testResult=" + this.testResult
          + ", testError=" + this.testError + ", testException=" + this.testException
          + ", reloadResult=" + this.reloadResult + ", reloadError=" + this.reloadError
          + ", reloadException=" + this.reloadException + ")";
    }

    /**
     * Builder for {@link MonitorStatus} objects.
     */
    public static class MonitorStatusBuilder {

      private String credentialName;

      private String testResult;

      private String testError;

      private String testException;

      private String reloadResult;

      private String reloadError;

      private String reloadException;

      /**
       * Default constructor.
       */
      MonitorStatusBuilder() {
      }

      /**
       * Assigns the credential name.
       *
       * @param credentialName the credential name
       * @return the builder
       */
      public MonitorStatusBuilder credentialName(final String credentialName) {
        this.credentialName = credentialName;
        return this;
      }

      /**
       * Assigns the test result.
       *
       * @param testResult the test result
       * @return the builder
       */
      public MonitorStatusBuilder testResult(final String testResult) {
        this.testResult = testResult;
        return this;
      }

      /**
       * Assigns the test error message.
       *
       * @param testError the test error message
       * @return the builder
       */
      public MonitorStatusBuilder testError(final String testError) {
        this.testError = testError;
        return this;
      }

      /**
       * Assigns the test exception class name.
       *
       * @param testException the test exception class name
       * @return the builder
       */
      public MonitorStatusBuilder testException(final String testException) {
        this.testException = testException;
        return this;
      }

      /**
       * Assigns the reload result.
       *
       * @param reloadResult the reload result
       * @return the builder
       */
      public MonitorStatusBuilder reloadResult(final String reloadResult) {
        this.reloadResult = reloadResult;
        return this;
      }

      /**
       * Assigns the reload error message.
       *
       * @param reloadError the reload error message
       * @return the builder
       */
      public MonitorStatusBuilder reloadError(final String reloadError) {
        this.reloadError = reloadError;
        return this;
      }

      /**
       * Assigns the reload exception class name.
       *
       * @param reloadException the reload exception class name
       * @return the builder
       */
      public MonitorStatusBuilder reloadException(final String reloadException) {
        this.reloadException = reloadException;
        return this;
      }

      /**
       * Builds the {@link MonitorStatus} object.
       *
       * @return a {@link MonitorStatus} object
       */
      public MonitorStatus build() {
        return new MonitorStatus(this.credentialName, this.testResult, this.testError, this.testException,
            this.reloadResult, this.reloadError, this.reloadException);
      }
    }

  }

}
