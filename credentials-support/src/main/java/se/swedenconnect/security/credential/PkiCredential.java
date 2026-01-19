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
package se.swedenconnect.security.credential;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

/**
 * A representation of a PKI key pair that holds a private key and an X.509 certificate (or just a public key).
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface PkiCredential {

  /**
   * Gets the public key.
   *
   * @return the public key
   */
  @Nonnull
  PublicKey getPublicKey();

  /**
   * Gets the certificate holding the public key of the key pair. May be {@code null} depending on whether certificates
   * are handled by the implementing class.
   *
   * @return the certificate, or {@code null} if no certificate is configured for the credential
   */
  @Nullable
  default X509Certificate getCertificate() {
    return this.getCertificateChain().stream()
        .findFirst()
        .orElse(null);
  }

  /**
   * Gets a certificate chain for the credential, where the first element is the entity certificate
   * ({@link #getCertificate()}). If no certificate is configured for the credential an empty list is returned.
   *
   * @return a list of certificates, or an empty list
   */
  @Nonnull
  List<X509Certificate> getCertificateChain();

  /**
   * Gets the private key.
   *
   * @return the private key
   */
  @Nonnull
  PrivateKey getPrivateKey();

  /**
   * Gets the credential metadata.
   *
   * @return a (potentially empty) credential metadata object
   */
  @Nonnull
  Metadata getMetadata();

  /**
   * Gets the name of the credential.
   *
   * @return the name
   */
  @Nonnull
  String getName();

  /**
   * Predicate that tells whether this credential resides in a hardware module.
   *
   * @return {@code true} if the credential resides in a hardware module and {@code false} otherwise
   */
  default boolean isHardwareCredential() {
    return false;
  }

  /**
   * Optional destroy method for credentials that need to perform cleaning up.
   */
  default void destroy() {
  }

  /**
   * Transforms the credential to another format, for example an JWK or a {@link java.security.KeyPair KeyPair}.
   *
   * @param transformFunction the transform function
   * @param <T> the type of the new format
   * @return the new format
   */
  default <T> T transform(@Nonnull final Function<PkiCredential, T> transformFunction) {
    return transformFunction.apply(this);
  }

  /**
   * Metadata associated with a {@link PkiCredential}.
   * <p>
   * Implementations may add any type of metadata to a credential. However, some XXX
   * </p>
   */
  interface Metadata {

    /** Property name for the key identifier metadata property. This property holds a {@link String}. */
    String KEY_ID_PROPERTY = "key-id";

    /** Property name for the {@link Instant} when the credential was issued. */
    String ISSUED_AT_PROPERTY = "issued-at";

    /**
     * Property name for the {@link Instant} when the credential expires. Note that this may be different from the
     * instant holding the {@link #ACTIVE_TO_PROPERTY} property.
     */
    String EXPIRES_AT_PROPERTY = "expires-at";

    /**
     * Property that may be set to the {@link Instant} at which the credential no longer should be regarded as active.
     */
    String ACTIVE_TO_PROPERTY = "active-to";

    /**
     * Property that may be set to the {@link Instant} from when the credential should be regarded as active.
     */
    String ACTIVE_FROM_PROPERTY = "active-from";

    /**
     * Property name for the usage property. This property holds a {@link String}, that may be {@value #USAGE_SIGNING},
     * {@value #USAGE_ENCRYPTION}, {@value #USAGE_METADATA_SIGNING} or any other application specific usage.
     */
    String USAGE_PROPERTY = "usage";

    /** Usage value indicating that a credential is used for signing. */
    String USAGE_SIGNING = "signing";

    /** Usage value indicating that a credential is used for encryption. */
    String USAGE_ENCRYPTION = "encryption";

    /**
     * Usage value indicating that a credential is used for metadata signing, for example SAML metadata, or OIDC entity
     * statements.
     */
    String USAGE_METADATA_SIGNING = "metadata-signing";

    /**
     * Assigns the key identifier ({@value #KEY_ID_PROPERTY} property).
     *
     * @param keyId the key identifier, or {@code null} to reset the value
     */
    default void setKeyId(@Nullable final String keyId) {
      this.getProperties().put(KEY_ID_PROPERTY, keyId);
    }

    /**
     * Gets the stored key identifier ({@value #KEY_ID_PROPERTY} property).
     *
     * @return the credential key identifier, or {@code null}, if not assigned
     */
    @Nullable
    default String getKeyId() {
      return (String) this.getProperties().get(KEY_ID_PROPERTY);
    }

    /**
     * Assigns the credential usage represented by the {@value #USAGE_PROPERTY} property.
     *
     * @param usage the usage string, or {@code null} to reset the {@value #USAGE_PROPERTY} property.
     */
    default void setUsage(@Nullable final String usage) {
      this.getProperties().put(USAGE_PROPERTY, usage);
    }

    /**
     * Gets the value for the {@value #USAGE_PROPERTY} property.
     *
     * @return a credential usage string or {@code null}
     */
    @Nullable
    default String getUsage() {
      return (String) this.getProperties().get(USAGE_PROPERTY);
    }

    /**
     * Assigns the {@link Instant} from when the credential should be regarded as active. Stored using the
     * {@value #ACTIVE_FROM_PROPERTY} property.
     *
     * @param activeFrom the active-from instant, or {@code null} for resetting the property
     */
    default void setActiveFrom(@Nullable final Instant activeFrom) {
      this.getProperties().put(ACTIVE_FROM_PROPERTY, activeFrom);
    }

    /**
     * Gets the {@link Instant} for the {@value #ACTIVE_FROM_PROPERTY} property.
     *
     * @return an {@link Instant} or {@code null}
     */
    @Nullable
    default Instant getActiveFrom() {
      return Optional.ofNullable(this.getProperties().get(ACTIVE_FROM_PROPERTY))
          .map(Metadata::toInstant)
          .orElse(null);
    }

    /**
     * Assigns the {@link Instant} for when the credential should no longer be active. Stored using the
     * {@value #ACTIVE_TO_PROPERTY} property.
     *
     * @param activeTo the active-to instant, or {@code null} for resetting the property
     */
    default void setActiveTo(@Nullable final Instant activeTo) {
      this.getProperties().put(ACTIVE_TO_PROPERTY, activeTo);
    }

    /**
     * Gets the {@link Instant} for the {@value #ACTIVE_TO_PROPERTY} property.
     *
     * @return an {@link Instant} or {@code null}
     */
    @Nullable
    default Instant getActiveTo() {
      return Optional.ofNullable(this.getProperties().get(ACTIVE_TO_PROPERTY))
          .map(Metadata::toInstant)
          .orElse(null);
    }

    /**
     * The instant for when the key pair/credential was issued.
     * <p>
     * If not explicitly assigned, implementations may use the {@code notBefore} property from the credential entity
     * certificate.
     * </p>
     *
     * @return an instant for when the credential was issued/created, or {@code null} if this information is not
     *     available
     */
    @Nullable
    default Instant getIssuedAt() {
      return Optional.ofNullable(this.getProperties().get(ISSUED_AT_PROPERTY))
          .map(Metadata::toInstant)
          .orElse(null);
    }

    /**
     * The instant for when the key pair/credential "expires".
     * <p>
     * If not explicitly assigned, implementations may use the {@code notAfter} property from the credential entity
     * certificate.
     * </p>
     *
     * @return an instant for when the credential expires, or {@code null} if this information is not available
     */
    @Nullable
    default Instant getExpiresAt() {
      return Optional.ofNullable(this.getProperties().get(EXPIRES_AT_PROPERTY))
          .map(Metadata::toInstant)
          .orElse(null);
    }

    /**
     * Gets a live map of the additional metadata properties.
     *
     * @return a (possibly empty) map of additional metadata properties
     */
    @Nonnull
    Map<String, Object> getProperties();

    @Nonnull
    private static Instant toInstant(@Nonnull final Object instant) {
      if (instant instanceof final Instant instantValue) {
        return instantValue;
      }
      else if (instant instanceof final String instantValue) {
        return Instant.parse(instantValue);
      }
      else {
        throw new IllegalArgumentException("Invalid instant type: " + instant.getClass());
      }
    }

  }

}
