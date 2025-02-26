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
package se.swedenconnect.security.credential.config.properties;

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.security.credential.config.BaseCredentialConfiguration;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Implementation of {@link BaseCredentialConfiguration}.
 *
 * @author Martin Lindström
 */
public class AbstractBaseCredentialConfigurationProperties implements BaseCredentialConfiguration {

  /**
   * The name of the credential.
   */
  @Setter
  @Getter
  private String name;

  /**
   * Key identifier metadata property.
   */
  @Setter
  @Getter
  private String keyId;

  /**
   * Issued-at metadata property.
   */
  @Setter
  @Getter
  private Instant issuedAt;

  /**
   * Expires-at metadata property.
   */
  @Setter
  @Getter
  private Instant expiresAt;

  /**
   * Credential metadata properties.
   */
  @Getter
  private final Map<String, String> metadata = new HashMap<>();

  /** {@inheritDoc} */
  @Override
  public Optional<String> name() {
    return Optional.ofNullable(this.getName());
  }

  /** {@inheritDoc} */
  @Override
  public Optional<String> keyId() {
    return Optional.ofNullable(this.getKeyId());
  }

  /** {@inheritDoc} */
  @Override
  public Optional<Instant> issuedAt() {
    return Optional.ofNullable(this.getIssuedAt());
  }

  /** {@inheritDoc} */
  @Override
  public Optional<Instant> expiresAt() {
    return Optional.ofNullable(this.getExpiresAt());
  }

  /** {@inheritDoc} */
  @Override
  public Optional<Map<String, String>> metadata() {
    return Optional.of(this.getMetadata());
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
    final AbstractBaseCredentialConfigurationProperties that = (AbstractBaseCredentialConfigurationProperties) o;
    return Objects.equals(this.name, that.name) && Objects.equals(this.keyId, that.keyId)
        && Objects.equals(this.issuedAt, that.issuedAt) && Objects.equals(this.expiresAt, that.expiresAt)
        && Objects.equals(this.metadata, that.metadata);
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hash(this.name, this.keyId, this.issuedAt, this.expiresAt, this.metadata);
  }

}
