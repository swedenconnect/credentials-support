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
package se.swedenconnect.security.credential;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Abstract base class for classes implementing the {@link PkiCredential} interface.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public abstract class AbstractPkiCredential implements PkiCredential {

  /** Logger instance. */
  private static final Logger log = LoggerFactory.getLogger(AbstractPkiCredential.class);

  /** The credential name. */
  private String name;

  /** The credential metadata. */
  private final Metadata metadata;

  /**
   * Default constructor.
   */
  public AbstractPkiCredential() {
    this.metadata = new Metadata() {

      private final Map<String, Object> properties = new HashMap<>();

      @Nonnull
      @Override
      public Map<String, Object> getProperties() {
        return this.properties;
      }
    };
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public PublicKey getPublicKey() {
    return Optional.ofNullable(this.getCertificate())
        .map(X509Certificate::getPublicKey)
        .orElseGet(() -> Optional.ofNullable(this.getStandalonePublicKey())
            .orElseThrow(() -> new IllegalArgumentException("No public key found")));
  }

  /**
   * If a credential without a certificate is created, this method must be overridden and return the installed
   * {@link PublicKey}.
   *
   * @return the standalone public key, or {@code null} if a certificate is present
   */
  @Nullable
  protected PublicKey getStandalonePublicKey() {
    return null;
  }

  /**
   * Gets the name of the credential. If no name has been explicitly assigned, the default name is used.
   */
  @Override
  @Nonnull
  public String getName() {
    return Optional.ofNullable(this.name).orElseGet(this::getDefaultName);
  }

  /**
   * Assigns the credential name.
   *
   * @param name the name
   */
  public void setName(@Nonnull final String name) {
    this.name = name;
  }

  /**
   * If the credential {@code name} property is not explicitly assigned using {@link #setName(String)} a name is
   * calculated based on a credential's properties.
   *
   * @return the credential name
   */
  @Nonnull
  protected abstract String getDefaultName();

  /** {@inheritDoc} */
  @Nonnull
  @Override
  public Metadata getMetadata() {
    return this.metadata;
  }

  /**
   * Updates the metadata properties issued-at and expires-at based on the entity certificate of the credential.
   */
  protected void updateMetadataValidityProperties() {
    final X509Certificate certificate = this.getCertificate();
    if (certificate == null) {
      log.debug("Credential does not have a certificate - can not update metadata validity properties");
      return;
    }
    if (this.getMetadata().getIssuedAt() == null) {
      Optional.ofNullable(certificate.getNotBefore())
          .ifPresent(d -> this.getMetadata().getProperties().put(Metadata.ISSUED_AT_PROPERTY, d.toInstant()));
      log.debug("Assigned metadata property '{}' with value '{}'",
          Metadata.ISSUED_AT_PROPERTY, this.getMetadata().getIssuedAt());
    }
    if (this.getMetadata().getExpiresAt() == null) {
      Optional.ofNullable(certificate.getNotAfter())
          .ifPresent(d -> this.getMetadata().getProperties().put(Metadata.EXPIRES_AT_PROPERTY, d.toInstant()));
      log.debug("Assigned metadata property '{}' with value '{}'",
          Metadata.EXPIRES_AT_PROPERTY, this.getMetadata().getExpiresAt());
    }
  }

}
