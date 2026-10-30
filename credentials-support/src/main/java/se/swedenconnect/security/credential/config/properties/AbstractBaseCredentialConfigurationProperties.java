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

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
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
  private String name;

  /**
   * Key identifier metadata property.
   */
  private String keyId;

  /**
   * Issued-at metadata property.
   */
  private Instant issuedAt;

  /**
   * Expires-at metadata property.
   */
  private Instant expiresAt;

  /**
   * Active-from metadata property.
   */
  private Instant activeFrom;

  /**
   * Active-to metadata property.
   */
  private Instant activeTo;

  /**
   * The usage metadata property.
   */
  private String usage;

  /**
   * Credential metadata properties.
   */
  private final Map<String, String> metadata = new HashMap<>();

  /**
   * Gets the name of the credential.
   *
   * @return the credential name
   */
  @Nullable
  public String getName() {
    return this.name;
  }

  /**
   * Assigns the name of the credential.
   *
   * @param name the credential name
   */
  public void setName(@Nullable final String name) {
    this.name = name;
  }

  /**
   * Gets the key identifier metadata property.
   *
   * @return the key identifier
   */
  @Nullable
  public String getKeyId() {
    return this.keyId;
  }

  /**
   * Assigns the key identifier metadata property.
   *
   * @param keyId the key identifier
   */
  public void setKeyId(@Nullable final String keyId) {
    this.keyId = keyId;
  }

  /**
   * Gets the issued-at metadata property.
   *
   * @return the issued-at instant
   */
  @Nullable
  public Instant getIssuedAt() {
    return this.issuedAt;
  }

  /**
   * Assigns the issued-at metadata property.
   *
   * @param issuedAt the issued-at instant
   */
  public void setIssuedAt(@Nullable final Instant issuedAt) {
    this.issuedAt = issuedAt;
  }

  /**
   * Gets the expires-at metadata property.
   *
   * @return the expires-at instant
   */
  @Nullable
  public Instant getExpiresAt() {
    return this.expiresAt;
  }

  /**
   * Assigns the expires-at metadata property.
   *
   * @param expiresAt the expires-at instant
   */
  public void setExpiresAt(@Nullable final Instant expiresAt) {
    this.expiresAt = expiresAt;
  }

  /**
   * Gets the active-from metadata property.
   *
   * @return the active-from instant
   */
  @Nullable
  public Instant getActiveFrom() {
    return this.activeFrom;
  }

  /**
   * Assigns the active-from metadata property.
   *
   * @param activeFrom the active-from instant
   */
  public void setActiveFrom(@Nullable final Instant activeFrom) {
    this.activeFrom = activeFrom;
  }

  /**
   * Gets the active-to metadata property.
   *
   * @return the active-to instant
   */
  @Nullable
  public Instant getActiveTo() {
    return this.activeTo;
  }

  /**
   * Assigns the active-to metadata property.
   *
   * @param activeTo the active-to instant
   */
  public void setActiveTo(@Nullable final Instant activeTo) {
    this.activeTo = activeTo;
  }

  /**
   * Gets the usage metadata property.
   *
   * @return the usage
   */
  @Nullable
  public String getUsage() {
    return this.usage;
  }

  /**
   * Assigns the usage metadata property.
   *
   * @param usage the usage
   */
  public void setUsage(@Nullable final String usage) {
    this.usage = usage;
  }

  /**
   * Gets the credential metadata properties.
   *
   * @return a (mutable) map of metadata properties
   */
  @Nonnull
  public Map<String, String> getMetadata() {
    return this.metadata;
  }

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
  public Optional<Instant> activeFrom() {
    return Optional.ofNullable(this.getActiveFrom());
  }

  /** {@inheritDoc} */
  @Override
  public Optional<Instant> activeTo() {
    return Optional.ofNullable(this.getActiveTo());
  }

  /** {@inheritDoc} */
  @Override
  public Optional<String> usage() {
    return Optional.ofNullable(this.getUsage());
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
        && Objects.equals(this.activeFrom, that.activeFrom) && Objects.equals(this.activeTo, that.activeTo)
        && Objects.equals(this.usage, that.usage) && Objects.equals(this.metadata, that.metadata);
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hash(this.name, this.keyId, this.issuedAt, this.expiresAt, this.activeFrom, this.activeTo,
        this.usage, this.metadata);
  }

}
