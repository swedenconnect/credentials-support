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
package se.swedenconnect.security.credential.spring.monitoring;

import jakarta.annotation.Nonnull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import se.swedenconnect.security.credential.ReloadablePkiCredential;
import se.swedenconnect.security.credential.spring.monitoring.events.FailedCredentialReloadEvent;
import se.swedenconnect.security.credential.spring.monitoring.events.FailedCredentialTestEvent;
import se.swedenconnect.security.credential.spring.monitoring.events.SuccessfulCredentialReloadEvent;
import se.swedenconnect.security.credential.spring.monitoring.events.SuccessfulCredentialTestEvent;

import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Consumer;

/**
 * Callbacks for credential monitoring signalling application events.
 *
 * @author Martin Lindström
 */
public class CredentialMonitoringCallbacks {

  /** Logger instance. */
  private static final Logger log = LoggerFactory.getLogger(CredentialMonitoringCallbacks.class);

  /** The system event publisher. */
  private final ApplicationEventPublisher eventPublisher;

  /**
   * Constructor.
   *
   * @param eventPublisher the system event publisher
   */
  public CredentialMonitoringCallbacks(final ApplicationEventPublisher eventPublisher) {
    this.eventPublisher = eventPublisher;
  }

  /**
   * Gets a callback for successful credential tests.
   *
   * @return a callback for successful credential tests
   */
  @Nonnull
  public Consumer<ReloadablePkiCredential> getTestSuccessCallback() {
    return cred -> {
      log.debug("Issuing {} for '{}'", SuccessfulCredentialTestEvent.class.getSimpleName(), cred.getName());
      this.eventPublisher.publishEvent(new SuccessfulCredentialTestEvent(cred.getName()));
    };
  }

  /**
   * Gets a callback for failed credential tests.
   *
   * @return a callback for failed credential tests
   */
  @Nonnull
  public BiFunction<ReloadablePkiCredential, Exception, Boolean> getTestFailureCallback() {
    return (cred, ex) -> {
      log.debug("Issuing {} for '{}' - error: {}",
          FailedCredentialTestEvent.class.getSimpleName(), cred.getName(), ex.getMessage());
      this.eventPublisher.publishEvent(
          new FailedCredentialTestEvent(cred.getName(), ex.getMessage(), ex.getClass().getName()));
      return true;
    };
  }

  /**
   * Gets a callback for successful credential reloads.
   *
   * @return a callback for successful credential reloads
   */
  @Nonnull
  public Consumer<ReloadablePkiCredential> getReloadSuccessCallback() {
    return cred -> {
      log.debug("Issuing {} for '{}'", SuccessfulCredentialReloadEvent.class.getSimpleName(), cred.getName());
      this.eventPublisher.publishEvent(new SuccessfulCredentialReloadEvent(cred.getName()));
    };
  }

  /**
   * Gets a callback for failed credential reloads.
   *
   * @return a callback for failed credential reloads
   */
  @Nonnull
  public BiConsumer<ReloadablePkiCredential, Exception> getReloadFailureCallback() {
    return (cred, ex) -> {
      log.debug("Issuing {} for '{}' - error: {}",
          FailedCredentialReloadEvent.class.getSimpleName(), cred.getName(), ex.getMessage());
      this.eventPublisher.publishEvent(
          new FailedCredentialReloadEvent(cred.getName(), ex.getMessage(), ex.getClass().getName()));
    };
  }

}
