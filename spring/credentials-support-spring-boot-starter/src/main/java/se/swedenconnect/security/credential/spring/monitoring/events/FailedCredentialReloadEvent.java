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
package se.swedenconnect.security.credential.spring.monitoring.events;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.swedenconnect.security.credential.LibraryVersion;

import java.io.Serial;
import java.util.Objects;

/**
 * Event that is signalled when a credential has been reloaded with an error.
 *
 * @author Martin Lindström
 */
public class FailedCredentialReloadEvent extends AbstractCredentialMonitoringEvent {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** The error message. */
  private final String error;

  /** The name of the exception that led to the error. */
  private final String exception;

  /**
   * Constructor.
   *
   * @param credentialName the name of the credential that was reloaded
   * @param error the error message
   * @param exception the name of the exception that led to the error
   */
  public FailedCredentialReloadEvent(
      @Nonnull final String credentialName, @Nonnull final String error, @Nullable final String exception) {
    super(credentialName);
    this.error = Objects.requireNonNull(error, "error must not be null");
    this.exception = exception;
  }

  /**
   * Gets the error message for the test.
   *
   * @return the error message for the test
   */
  @Nonnull
  public String getError() {
    return this.error;
  }

  /**
   * Gets the name of the exception that led to the error.
   *
   * @return the name of the exception that led to the error, or {@code null}
   */
  @Nullable
  public String getException() {
    return this.exception;
  }

}
