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
package se.swedenconnect.security.credential.config;

import java.util.List;
import java.util.Optional;
import java.util.function.Function;

/**
 * Configuration interface for configuring a
 * {@link se.swedenconnect.security.credential.PkiCredentialCollection PkiCredentialCollection}.
 * <p>
 * See also
 * {@link
 * se.swedenconnect.security.credential.factory.PkiCredentialFactory#createCredentialCollection(PkiCredentialCollectionConfiguration)}
 * and
 * {@link se.swedenconnect.security.credential.factory.PkiCredentialFactory#createCredential(PkiCredentialConfiguration,
 * ConfigurationResourceLoader, Function, Function, Function)}.
 * </p>
 *
 * @author Martin Lindström
 */
public interface PkiCredentialCollectionConfiguration {

  /**
   * A list of {@link PkiCredentialConfiguration} objects for the credentials that are to be present in the resulting
   * {@link se.swedenconnect.security.credential.PkiCredentialCollection PkiCredentialCollection}.
   *
   * @return a list of {@link PkiCredentialConfiguration} objects
   */
  Optional<List<PkiCredentialConfiguration>> credentials();
}
