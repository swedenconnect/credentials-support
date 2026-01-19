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
package se.swedenconnect.security.credential.spring.monitoring.events;

import jakarta.annotation.Nonnull;
import org.springframework.context.ApplicationEvent;
import se.swedenconnect.security.credential.LibraryVersion;

import java.io.Serial;
import java.util.Objects;

/**
 * Abstract base class for credential monitoring events.
 *
 * @author Martin Lindström
 */
public class AbstractCredentialMonitoringEvent extends ApplicationEvent {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /**
   * Constructor.
   *
   * @param credentialName the name of the credential that was monitored
   */
  public AbstractCredentialMonitoringEvent(@Nonnull final String credentialName) {
    super(Objects.requireNonNull(credentialName, "credentialName must not be null"));
  }

  /**
   * Gets the name of the credential that was monitored.
   *
   * @return the credential name
   */
  @Nonnull
  public String getCredentialName() {
    return (String) this.getSource();
  }

}
