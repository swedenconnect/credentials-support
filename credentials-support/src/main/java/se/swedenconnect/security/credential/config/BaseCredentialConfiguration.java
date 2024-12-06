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
package se.swedenconnect.security.credential.config;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;

/**
 * Base configuration interface for creating a
 * {@link se.swedenconnect.security.credential.PkiCredential PkiCredential}.
 *
 * @author Martin Lindström
 */
public interface BaseCredentialConfiguration {

  /**
   * The name of the credential.
   *
   * @return the name of the credential
   */
  Optional<String> name();

  /**
   * Metadata property for key identifier.
   *
   * @return property for key identifier
   */
  Optional<String> keyId();

  /**
   * Metadata property for issued-at.
   *
   * @return property for issued-at
   */
  Optional<Instant> issuedAt();

  /**
   * Metadata property for expires-at.
   *
   * @return property for expires-at
   */
  Optional<Instant> expiresAt();

  /**
   * Additional metadata properties.
   *
   * @return additional metadata properties
   */
  Optional<Map<String, String>> metadata();

}
