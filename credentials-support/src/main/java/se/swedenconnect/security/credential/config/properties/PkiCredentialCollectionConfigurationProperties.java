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
package se.swedenconnect.security.credential.config.properties;

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.security.credential.config.ConfigurationResourceLoader;
import se.swedenconnect.security.credential.config.PkiCredentialCollectionConfiguration;
import se.swedenconnect.security.credential.config.PkiCredentialConfiguration;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Configuration properties for creating a
 * {@link se.swedenconnect.security.credential.PkiCredentialCollection PkiCredentialCollection}.
 *
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
public class PkiCredentialCollectionConfigurationProperties implements PkiCredentialCollectionConfiguration {

  /**
   * The credentials that are part of the credential collection.
   */
  @Setter
  @Getter
  private List<PkiCredentialConfigurationProperties> credentials;

  /** {@inheritDoc} */
  @Override
  public Optional<List<PkiCredentialConfiguration>> credentials() {
    return Optional.ofNullable(this.getCredentials()).map(ArrayList::new);
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
    final PkiCredentialCollectionConfigurationProperties that = (PkiCredentialCollectionConfigurationProperties) o;
    return Objects.equals(this.credentials, that.credentials);
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hashCode(this.credentials);
  }

}
