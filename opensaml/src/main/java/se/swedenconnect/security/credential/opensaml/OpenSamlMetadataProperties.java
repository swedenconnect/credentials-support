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
package se.swedenconnect.security.credential.opensaml;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.swedenconnect.security.credential.PkiCredential;

import java.util.List;
import java.util.Optional;

/**
 * Symbolic constants for storing OpenSAML specific properties in a
 * {@link se.swedenconnect.security.credential.PkiCredential.Metadata PkiCredential.Metadata} object.
 *
 * @author Martin Lindström
 */
public class OpenSamlMetadataProperties {

  /**
   * Property name for assigning a SAML entity ID to the credential metadata. Holds a {@link String}.
   */
  public static final String ENTITY_ID_PROPERTY = "entity-id";

  /**
   * Property name for holding {@code md:EncryptionMethod}. This property holds a {@link java.util.List List} of
   * {@link EncryptionMethodMetadata} objects.
   */
  public static final String ENCRYPTION_METHODS = "encryption-methods";

  /**
   * Assigns the entityID property to the metadata.
   *
   * @param metadata the metadata to update
   * @param entityId the entity ID - if {@code null}, the property is reset
   */
  public static void setEntityId(@Nonnull final PkiCredential.Metadata metadata, @Nullable final String entityId) {
    metadata.getProperties().put(ENTITY_ID_PROPERTY, entityId);
  }

  /**
   * Gets the entityID property.
   *
   * @param metadata the metadata
   * @return an entityID {@link String}, or {@code null}
   */
  @Nullable
  public static String getEntityId(@Nonnull final PkiCredential.Metadata metadata) {
    return (String) metadata.getProperties().get(ENTITY_ID_PROPERTY);
  }

  /**
   * Assigns the encryption methods given the string representation (see
   * {@link EncryptionMethodMetadata#parseMethods(String)}) of the methods.
   *
   * @param metadata the metadata to update
   * @param encryptionMethods the methods in string representation
   */
  public static void setEncryptionMethods(
      @Nonnull final PkiCredential.Metadata metadata, @Nullable final String encryptionMethods) {
    Optional.ofNullable(encryptionMethods)
        .map(EncryptionMethodMetadata::parseMethods)
        .ifPresentOrElse(m -> setEncryptionMethods(metadata, m),
            () -> metadata.getProperties().remove(ENCRYPTION_METHODS));
  }

  /**
   * Assigns the encryption methods property.
   *
   * @param metadata the metadata to update
   * @param encryptionMethods the methods
   */
  public static void setEncryptionMethods(@Nonnull final PkiCredential.Metadata metadata,
      @Nullable final List<EncryptionMethodMetadata> encryptionMethods) {
    metadata.getProperties().put(ENCRYPTION_METHODS, encryptionMethods);
  }

  /**
   * Gets the encryption methods property from the supplied metadata.
   *
   * @param metadata the metadata
   * @return a list of methods, or {@code null}
   */
  @Nullable
  public static List<EncryptionMethodMetadata> getEncryptionMethods(@Nonnull final PkiCredential.Metadata metadata) {
    return Optional.ofNullable(metadata.getProperties().get(ENCRYPTION_METHODS))
        .map(m -> m instanceof String ? EncryptionMethodMetadata.parseMethods((String) m)
            : (List<EncryptionMethodMetadata>) m)
        .orElse(null);
  }

  private OpenSamlMetadataProperties() {
  }
}
