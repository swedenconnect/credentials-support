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
package se.swedenconnect.security.credential;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;

/**
 * A collection of {@link PkiCredential} instances.
 * <p>
 * This class may be used as a bean for a system that uses several different keys, for example a SAML IdP that has a
 * signature key, an encryption key and possibly other keys. By using the predefined {@link Predicate}s, a credential
 * having the desired properties can be located.
 * </p>
 *
 * @author Martin Lindström
 */
public class PkiCredentialCollection {

  /** The credentials held by this collection. */
  private final List<PkiCredential> credentials;

  /**
   * Constructor.
   *
   * @param credentials the credentials to store in the collection
   */
  public PkiCredentialCollection(@Nonnull final List<PkiCredential> credentials) {
    this.credentials = new ArrayList<>(
        Objects.requireNonNull(credentials, "credentials must not be null"));
  }

  /**
   * Gets an unmodifiable list of all credentials held in the collection.
   *
   * @return the credentials
   */
  @Nonnull
  public List<PkiCredential> getCredentials() {
    return Collections.unmodifiableList(this.credentials);
  }

  /**
   * Returns the first credential of the collection whose properties meet the supplied {@link Predicate}.
   *
   * @param predicate the {@link Predicate}
   * @return the first credential whose properties meet the supplied predicate, or {@code null} if no match is found
   */
  @Nullable
  public PkiCredential getCredential(@Nonnull final Predicate<PkiCredential> predicate) {
    return this.credentials.stream().filter(predicate).findFirst().orElse(null);
  }

  /**
   * Returns all credentials whose properties meet the supplied {@link Predicate}.
   *
   * @param predicate the {@link Predicate}
   * @return a unmodifiable list of all matching credentials (may be empty)
   */
  @Nonnull
  public List<PkiCredential> getCredentials(@Nonnull final Predicate<PkiCredential> predicate) {
    return this.credentials.stream().filter(predicate).toList();
  }

  /**
   * Adds a credential to the collection.
   *
   * @param credential the credential to add
   */
  public void addCredential(@Nonnull final PkiCredential credential) {
    this.credentials.add(Objects.requireNonNull(credential, "credential must not be null"));
  }

  /**
   * Removes all credentials matching the supplied {@link Predicate}.
   *
   * @param predicate the {@link Predicate}
   * @return a list of the credentials that were removed from the collection
   */
  @Nonnull
  public List<PkiCredential> removeCredentials(@Nonnull final Predicate<PkiCredential> predicate) {
    final ArrayList<PkiCredential> removed = new ArrayList<>();
    final Iterator<PkiCredential> it = this.credentials.iterator();
    while (it.hasNext()) {
      final PkiCredential c = it.next();
      if (predicate.test(c)) {
        removed.add(c);
        it.remove();
      }
    }
    return removed;
  }

  /**
   * {@link Predicate} that tells whether a credential holds an RSA key.
   */
  public static Predicate<PkiCredential> isRsa = c -> c.getPublicKey().getAlgorithm().equals("RSA");

  /**
   * {@link Predicate} that tells whether a credential holds an EC key.
   */
  public static Predicate<PkiCredential> isEc = c -> c.getPublicKey().getAlgorithm().equals("EC");

  /**
   * {@link Predicate} that tells whether a credential is a hardware credential, i.e., stored on an HSM.
   */
  public static Predicate<PkiCredential> isHardwareCredential = PkiCredential::isHardwareCredential;

  /**
   * Method that returns a {@link Predicate} that checks if a credential has a given key ID.
   * <p>
   * The implementation will look for the credential metadata entry {@value PkiCredential.Metadata#KEY_ID_PROPERTY}.
   * </p>
   *
   * @param kid the key ID to check for
   * @return a {@link Predicate}
   */
  public static Predicate<PkiCredential> keyId(@Nonnull final String kid) {
    return c -> Optional.ofNullable(c.getMetadata().getKeyId())
        .filter(k -> k.equals(kid))
        .isPresent();
  }

  /**
   * Method that returns a {@link Predicate} that checks if a credential has a given usage.
   * <p>
   * The implementation will look for the credential metadata entry {@link PkiCredential.Metadata#USAGE_PROPERTY}.
   * </p>
   *
   * @param usage the usage to check
   * @return a {@link Predicate}
   */
  public static Predicate<PkiCredential> usage(@Nonnull final String usage) {
    return c -> Optional.ofNullable(c.getMetadata().getUsage())
        .filter(u -> u.equalsIgnoreCase(usage))
        .isPresent();
  }

  /**
   * {@link Predicate} that checks if the credential has the {@link PkiCredential.Metadata#USAGE_SIGNING} usage.
   */
  public static Predicate<PkiCredential> signatureUsage = usage(PkiCredential.Metadata.USAGE_SIGNING);

  /**
   * {@link Predicate} that checks if the credential has the {@link PkiCredential.Metadata#USAGE_ENCRYPTION} usage.
   */
  public static Predicate<PkiCredential> encryptionUsage = usage(PkiCredential.Metadata.USAGE_ENCRYPTION);

  /**
   * {@link Predicate} that checks if the credential does not have a specified usage.
   */
  public static Predicate<PkiCredential> unspecifiedUsage = c -> c.getMetadata().getUsage() == null;

  /**
   * Method that finds a credential suitable for signing. It first tries to find an active credential with the usage set
   * to {@link PkiCredential.Metadata#USAGE_SIGNING}, and if no such credential is found, an active credential with no
   * specified usage.
   *
   * @return a {@link PkiCredential} or {@code null}
   */
  @Nullable
  public PkiCredential getCredentialForSigning() {
    return Optional.ofNullable(this.getCredential(signatureUsage.and(isActive)))
        .orElseGet(() -> this.getCredential(unspecifiedUsage.and(isActive)));
  }

  /**
   * Method that finds credentials suitable for encryption (and decryption).
   *
   * @return a (possibly empty) list of credentials
   */
  @Nonnull
  public List<PkiCredential> getCredentialsForEncryption() {
    final ArrayList<PkiCredential> credentials = new ArrayList<>(this.getCredentials(encryptionUsage.and(isActive)));
    if (!credentials.isEmpty()) {
      // Add the previous encryption credentials ...
      credentials.addAll(this.getCredentials(encryptionUsage.and(noLongerActive)));
    }
    else {
      credentials.addAll(this.getCredentials(unspecifiedUsage.and(isActive)));
      credentials.addAll(
          Optional.of(this.getCredentials(encryptionUsage.and(noLongerActive)))
              .filter(c -> !c.isEmpty())
              .orElseGet(() -> this.getCredentials(unspecifiedUsage.and(noLongerActive))));
    }
    return credentials;
  }

  /**
   * {@link Predicate} that checks if the credential is "active", meaning that the current time is within the
   * {@link PkiCredential.Metadata#ACTIVE_FROM_PROPERTY} and {@link PkiCredential.Metadata#ACTIVE_TO_PROPERTY}
   * properties. If no such properties are set, the credential is assumed to be active.
   */
  public static Predicate<PkiCredential> isActive = c -> {
    final Instant now = Instant.now();
    final Instant activeTo = c.getMetadata().getActiveTo();
    if (activeTo != null && now.isAfter(activeTo)) {
      return false;
    }
    final Instant activeFrom = c.getMetadata().getActiveFrom();
    return activeFrom == null || !now.isBefore(activeFrom);
  };

  /**
   * {@link Predicate} that checks if the credential is no longer active, meaning that a
   * {@link PkiCredential.Metadata#ACTIVE_TO_PROPERTY} setting is before the current time.
   */
  public static Predicate<PkiCredential> noLongerActive =
      c -> Optional.ofNullable(c.getMetadata().getActiveTo())
          .map(Instant.now()::isAfter)
          .orElse(false);

  /**
   * {@link Predicate} that tells whether the credential is "not yet active", meaning that the
   * {@link PkiCredential.Metadata#ACTIVE_FROM_PROPERTY} setting is after the current time.
   */
  public static Predicate<PkiCredential> isNotYetActive =
      c -> Optional.ofNullable(c.getMetadata().getActiveFrom())
          .filter(af -> Instant.now().isBefore(af))
          .isPresent();

  /**
   * {@link Predicate} that tells if a credential is intended to be the signing credential in the future.
   */
  public static Predicate<PkiCredential> forFutureSigning = signatureUsage.and(isNotYetActive);

}
