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
package se.swedenconnect.security.credential.container;

import se.swedenconnect.security.credential.LibraryVersion;

import java.io.Serial;

/**
 * General exception for errors when managing PkiCredentials in a PkiCredentialContainer.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class PkiCredentialContainerException extends Exception {

  /** For serializing. */
  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /**
   * Constructor.
   *
   * @param message the error message
   */
  public PkiCredentialContainerException(final String message) {
    super(message);
  }

  /**
   * Constructor.
   *
   * @param message the error message
   * @param cause the cause of the error
   */
  public PkiCredentialContainerException(final String message, final Throwable cause) {
    super(message, cause);
  }

}
