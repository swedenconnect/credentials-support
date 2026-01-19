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
package se.swedenconnect.security.credential.nimbus;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyUse;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.swedenconnect.security.credential.PkiCredential;

import java.text.ParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Symbolic constants for storing JWK properties in a {@link PkiCredential.Metadata} object. The class also offers
 * utility methods for setting and getting JWK related properties.
 *
 * @author Martin Lindström
 */
public class JwkMetadataProperties {

  /**
   * Property name for the key use metadata property. Maps to JWK's {@code use} property. Should hold a {@link KeyUse}
   * or a {@link String}.
   */
  public static final String KEY_USE_PROPERTY = "key-use";

  /**
   * Property name for the key operations metadata property. Maps to JWK's {@code ops} property. Should hold a
   * {@link Set} of {@link KeyOperation}s or a comma-separated list of {@link String}s.
   */
  public static final String KEY_OPS_PROPERTY = "key-ops";

  /**
   * Property name for the JOSE algorithm metadata property. Maps to JWK's {@code alg} property. Should hold a
   * {@link com.nimbusds.jose.Algorithm Algorithm} or a {@link String} representation.
   */
  public static final String JOSE_ALGORITHM_PROPERTY = "jose-alg";

  /**
   * Utility method that is used to assign the {@value #KEY_USE_PROPERTY} property. See
   * {@link #setKeyUse(PkiCredential.Metadata, KeyUse)}.
   *
   * @param metadata the {@link PkiCredential.Metadata Metadata} object
   * @param keyUse the key use string
   */
  public static void setKeyUse(@Nonnull final PkiCredential.Metadata metadata, @Nullable final String keyUse) {
    setKeyUse(metadata, toKeyUse(keyUse));
  }

  /**
   * Utility method that is used to assign the {@value #KEY_USE_PROPERTY} property.
   * <p>
   * As a side-effect, the method will also update the {@link PkiCredential.Metadata#USAGE_PROPERTY}.
   * {@link KeyUse#SIGNATURE} maps to {@link PkiCredential.Metadata#USAGE_SIGNING} and {@link KeyUse#ENCRYPTION} maps to
   * {@link PkiCredential.Metadata#USAGE_ENCRYPTION}.
   * </p>
   * If the supplied {@link KeyUse} is {@link KeyUse#SIGNATURE} or {@link KeyUse#ENCRYPTION}
   *
   * @param metadata the {@link PkiCredential.Metadata Metadata} object
   * @param keyUse the key use
   */
  public static void setKeyUse(@Nonnull final PkiCredential.Metadata metadata, @Nullable final KeyUse keyUse) {
    if (keyUse == null) {
      metadata.getProperties().remove(KEY_USE_PROPERTY);
    }
    else {
      metadata.getProperties().put(KEY_USE_PROPERTY, keyUse);
      if (KeyUse.SIGNATURE.equals(keyUse)) {
        metadata.setUsage(PkiCredential.Metadata.USAGE_SIGNING);
      }
      else if (KeyUse.ENCRYPTION.equals(keyUse)) {
        metadata.setUsage(PkiCredential.Metadata.USAGE_ENCRYPTION);
      }
    }
  }

  /**
   * Gets the value of the {@value #KEY_USE_PROPERTY}.
   * <p>
   * If no value is stored for the {@value #KEY_USE_PROPERTY}, but a value exists for
   * {@link PkiCredential.Metadata#USAGE_PROPERTY}, this value is mapped to a {@link KeyUse}.
   * </p>
   *
   * @param metadata the {@link PkiCredential.Metadata Metadata} object
   * @return a {@link KeyUse} or {@code null}
   */
  @Nullable
  public static KeyUse getKeyUse(@Nonnull final PkiCredential.Metadata metadata) {
    final Object value = metadata.getProperties().get(KEY_USE_PROPERTY);
    if (value instanceof final KeyUse keyUse) {
      return keyUse;
    }
    else if (value instanceof final String keyUseString) {
      return toKeyUse(keyUseString);
    }
    else {
      return toKeyUse(metadata.getUsage());
    }
  }

  private static KeyUse toKeyUse(@Nullable final String use) {
    if (use == null) {
      return null;
    }
    if (PkiCredential.Metadata.USAGE_SIGNING.equals(use)) {
      return KeyUse.SIGNATURE;
    }
    else if (PkiCredential.Metadata.USAGE_ENCRYPTION.equals(use)) {
      return KeyUse.ENCRYPTION;
    }
    else {
      try {
        return KeyUse.parse(use);
      }
      catch (final ParseException e) {
        return null;
      }
    }
  }

  /**
   * Utility method that assigns the {@value #KEY_OPS_PROPERTY}. See {@link #setKeyOps(PkiCredential.Metadata, Set)}.
   *
   * @param metadata the {@link PkiCredential.Metadata Metadata} object
   * @param keyOps a list of key operations (or {@code null} for resetting the property)
   * @throws IllegalArgumentException for invalid key operations, see {@link KeyOperation#parse(List)}
   */
  public static void setKeyOps(@Nonnull final PkiCredential.Metadata metadata, @Nullable final List<String> keyOps)
      throws IllegalArgumentException {
    try {
      setKeyOps(metadata, KeyOperation.parse(keyOps));
    }
    catch (final ParseException e) {
      throw new IllegalArgumentException("Invalid key operation(s): " + keyOps, e);
    }
  }

  /**
   * Utility method that assigns the {@value #KEY_OPS_PROPERTY}. See {@link #setKeyOps(PkiCredential.Metadata, Set)}.
   *
   * @param metadata the {@link PkiCredential.Metadata Metadata} object
   * @param keyOps a comma-separated list of key operation strings (or {@code null} for resetting the property)
   * @throws IllegalArgumentException for invalid key operations, see {@link KeyOperation#parse(List)}
   */
  public static void setKeyOps(@Nonnull final PkiCredential.Metadata metadata, @Nullable final String keyOps)
      throws IllegalArgumentException {
    Optional.ofNullable(keyOps)
        .ifPresentOrElse(
            ko -> setKeyOps(metadata, Arrays.stream(ko.split(",")).map(String::trim).toList()),
            () -> metadata.getProperties().remove(KEY_OPS_PROPERTY));
  }

  /**
   * Utility method that assigns the {@value #KEY_OPS_PROPERTY}.
   *
   * @param metadata the {@link PkiCredential.Metadata Metadata} object
   * @param keyOps a set of key operations (or {@code null} for resetting the property)
   */
  public static void setKeyOps(
      @Nonnull final PkiCredential.Metadata metadata, @Nullable final Set<KeyOperation> keyOps) {
    metadata.getProperties().put(KEY_OPS_PROPERTY, keyOps);
  }

  /**
   * Gets the value for the {@value #KEY_OPS_PROPERTY} property.
   *
   * @param metadata the {@link PkiCredential.Metadata Metadata} object
   * @return a set of {@link KeyOperation}s, or {@code null}
   */
  @Nullable
  public static Set<KeyOperation> getKeyOps(@Nonnull final PkiCredential.Metadata metadata) {
    return Optional.ofNullable(metadata.getProperties().get(KEY_OPS_PROPERTY))
        .map(ko -> {
          if (ko instanceof final String stringValue) {
            try {
              return KeyOperation.parse(Arrays.stream(stringValue.split(",")).map(String::trim).toList());
            }
            catch (final ParseException e) {
              throw new RuntimeException(e);
            }
          }
          else {
            return (Set<KeyOperation>) ko;
          }
        })
        .orElse(null);
  }

  /**
   * Utility method that assigns the {@value #JOSE_ALGORITHM_PROPERTY}.
   *
   * @param metadata the {@link PkiCredential.Metadata Metadata} object
   * @param joseAlgorithm the string representation of the JOSE algorithm
   */
  public static void setJoseAlgorithm(
      @Nonnull final PkiCredential.Metadata metadata, @Nullable final String joseAlgorithm) {
    setJoseAlgorithm(metadata, Algorithm.parse(joseAlgorithm));
  }

  /**
   * Utility method that assigns the {@value #JOSE_ALGORITHM_PROPERTY}. See
   * {@link #setJoseAlgorithm(PkiCredential.Metadata, String)}.
   *
   * @param metadata the {@link PkiCredential.Metadata Metadata} object
   * @param joseAlgorithm the JOSE algorithm
   */
  public static void setJoseAlgorithm(
      @Nonnull final PkiCredential.Metadata metadata, @Nullable final Algorithm joseAlgorithm) {
    metadata.getProperties().put(JOSE_ALGORITHM_PROPERTY, joseAlgorithm);
  }

  /**
   * Gets the value of the {@value #JOSE_ALGORITHM_PROPERTY} property.
   *
   * @param metadata the {@link PkiCredential.Metadata Metadata} object
   * @return the JOSE {@link Algorithm} or {@code null}
   */
  @Nullable
  public static Algorithm getJoseAlgorithm(@Nonnull final PkiCredential.Metadata metadata) {
    return Optional.ofNullable(metadata.getProperties().get(JOSE_ALGORITHM_PROPERTY))
        .map(a -> a instanceof String ? Algorithm.parse((String) a) : (Algorithm) a)
        .orElse(null);
  }

  // Hidden
  private JwkMetadataProperties() {
  }
}
