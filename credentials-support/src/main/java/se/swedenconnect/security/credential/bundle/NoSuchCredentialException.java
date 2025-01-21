/*
 * Copyright 2020-2025 Sweden Connect
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
package se.swedenconnect.security.credential.bundle;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.swedenconnect.security.credential.LibraryVersion;

import java.io.Serial;
import java.util.Objects;

/**
 * Exception indicating that a {@link se.swedenconnect.security.credential.PkiCredential PkiCredential} was referenced
 * with an ID that does not match any registered credential.
 *
 * @author Martin Lindström
 */
public class NoSuchCredentialException extends RuntimeException {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** The credential ID. */
  private final String credentialId;

  /**
   * Constructor accepting the credential ID and a message.
   *
   * @param id the credential ID
   * @param message the message
   */
  public NoSuchCredentialException(@Nonnull final String id, @Nullable final String message) {
    this(id, message, null);
  }

  /**
   * Constructor accepting the credential ID, a message and the cause of the error.
   *
   * @param id the credential ID
   * @param message the message
   * @param cause the cause of the error
   */
  public NoSuchCredentialException(
      @Nonnull final String id, @Nullable final String message, @Nullable final Throwable cause) {
    super(message, cause);
    this.credentialId = Objects.requireNonNull(id, "id must not be null");
  }

  /**
   * Gets the credential ID.
   *
   * @return an ID
   */
  @Nonnull
  public String getCredentialId() {
    return this.credentialId;
  }

}
