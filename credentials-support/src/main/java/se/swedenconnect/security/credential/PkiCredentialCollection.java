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

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Predicate;

/**
 * A collection of {@link PkiCredential} instances.
 * <p>
 * This class may be used as a bean for a system that uses several different keys, for example a SAML IdP that has a
 * signature key, an encryption key and possibly other keys. By using the predefined {@link Predicate}s, a credential
 * having the desired properties can be located.
 * </p>
 * <p>
 * The lifecycle of a credential is given by the metadata properties
 * {@value PkiCredential.Metadata#ACTIVE_FROM_PROPERTY}, {@value PkiCredential.Metadata#ACTIVE_TO_PROPERTY} and
 * {@value PkiCredential.Metadata#REVOKED_AT_PROPERTY}. The collection evaluates these against the time given by its
 * {@link Clock}. This makes it possible to handle key rollover, where a new key is published before it is used, and an
 * old key is kept for a while after it is no longer used.
 * </p>
 * <p>
 * The collection is safe to use from several threads, also when credentials are added or removed.
 * </p>
 * <p>
 * The class may be used as a base class. Subclasses get the clock from {@link #getClock()}.
 * </p>
 *
 * @author Martin Lindström
 */
public class PkiCredentialCollection {

  /** The credentials held by this collection. */
  private final List<PkiCredential> credentials;

  /** The clock used when evaluating the lifecycle of credentials. */
  private final Clock clock;

  /**
   * Orders credentials so that the one with the latest {@value PkiCredential.Metadata#ACTIVE_FROM_PROPERTY} comes
   * first. A credential without this property counts as the oldest. The sort is stable, so the list order decides for
   * equal times.
   */
  private static final Comparator<PkiCredential> LATEST_ACTIVE_FROM_FIRST = Comparator.comparing(
      c -> c.getMetadata().getActiveFrom(), Comparator.nullsLast(Comparator.reverseOrder()));

  /**
   * Constructor using the system clock in UTC.
   *
   * @param credentials the credentials to store in the collection
   */
  public PkiCredentialCollection(@Nonnull final List<PkiCredential> credentials) {
    this(credentials, Clock.systemUTC());
  }

  /**
   * Constructor.
   *
   * @param credentials the credentials to store in the collection
   * @param clock the clock used when evaluating the lifecycle of credentials
   */
  public PkiCredentialCollection(@Nonnull final List<PkiCredential> credentials, @Nonnull final Clock clock) {
    this.credentials = new CopyOnWriteArrayList<>(
        Objects.requireNonNull(credentials, "credentials must not be null"));
    this.clock = Objects.requireNonNull(clock, "clock must not be null");
  }

  /**
   * Gets the clock used when evaluating the lifecycle of credentials.
   *
   * @return the clock
   */
  @Nonnull
  protected Clock getClock() {
    return this.clock;
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
    final List<PkiCredential> removed = new ArrayList<>();
    this.credentials.removeIf(c -> {
      if (predicate.test(c)) {
        removed.add(c);
        return true;
      }
      return false;
    });
    return removed;
  }

  /**
   * Gets the credentials that are active at the current time of the collection's clock. See
   * {@link #isActiveAt(Instant)}.
   *
   * @return an unmodifiable list of active credentials (may be empty)
   */
  @Nonnull
  public List<PkiCredential> getActiveCredentials() {
    return this.getCredentials(isActiveAt(this.clock.instant()));
  }

  /**
   * Gets the credentials that are not yet active at the current time of the collection's clock. See
   * {@link #isNotYetActiveAt(Instant)}.
   *
   * @return an unmodifiable list of credentials that are not yet active (may be empty)
   */
  @Nonnull
  public List<PkiCredential> getNotYetActiveCredentials() {
    return this.getCredentials(isNotYetActiveAt(this.clock.instant()));
  }

  /**
   * Gets the credentials that are no longer active at the current time of the collection's clock. This includes
   * revoked credentials. See {@link #isNoLongerActiveAt(Instant)}.
   *
   * @return an unmodifiable list of credentials that are no longer active (may be empty)
   */
  @Nonnull
  public List<PkiCredential> getNoLongerActiveCredentials() {
    return this.getCredentials(isNoLongerActiveAt(this.clock.instant()));
  }

  /**
   * Gets the credentials to publish, that is, the credentials that are active or not yet active at the current time of
   * the collection's clock.
   *
   * @return an unmodifiable list of credentials to publish (may be empty)
   */
  @Nonnull
  public List<PkiCredential> getCredentialsToPublish() {
    final Instant now = this.clock.instant();
    return this.getCredentials(isActiveAt(now).or(isNotYetActiveAt(now)));
  }

  /**
   * Method that finds a credential suitable for signing. See {@link #getCredentialForSigning(Predicate)}.
   *
   * @return a {@link PkiCredential} or {@code null}
   */
  @Nullable
  public PkiCredential getCredentialForSigning() {
    return this.getCredentialForSigning(c -> true);
  }

  /**
   * Method that finds a credential suitable for signing that also meets the supplied filter.
   * <p>
   * It first looks among the active credentials with the usage set to {@link PkiCredential.Metadata#USAGE_SIGNING},
   * and if none is found, among the active credentials with no specified usage. If several credentials match, the one
   * with the latest {@value PkiCredential.Metadata#ACTIVE_FROM_PROPERTY} is returned. A credential without this
   * property counts as the oldest, and for equal times, the one first in the collection is returned.
   * </p>
   *
   * @param filter a filter that the credential must meet, for example a check of the key type
   * @return a {@link PkiCredential} or {@code null}
   */
  @Nullable
  public PkiCredential getCredentialForSigning(@Nonnull final Predicate<PkiCredential> filter) {
    Objects.requireNonNull(filter, "filter must not be null");
    final Predicate<PkiCredential> active = isActiveAt(this.clock.instant()).and(filter);
    return this.getLatestActive(signatureUsage.and(active))
        .orElseGet(() -> this.getLatestActive(unspecifiedUsage.and(active)).orElse(null));
  }

  /**
   * Method that finds credentials suitable for encryption (and decryption). See
   * {@link #getCredentialsForEncryption(Predicate)}.
   *
   * @return a (possibly empty) list of credentials
   */
  @Nonnull
  public List<PkiCredential> getCredentialsForEncryption() {
    return this.getCredentialsForEncryption(c -> true);
  }

  /**
   * Method that finds credentials suitable for encryption (and decryption) that also meet the supplied filter.
   * <p>
   * The active credentials with the usage set to {@link PkiCredential.Metadata#USAGE_ENCRYPTION} come first, ordered so
   * that the one with the latest {@value PkiCredential.Metadata#ACTIVE_FROM_PROPERTY} is first. They are followed by
   * the encryption credentials that are no longer active, since these may be needed for decryption. If there are no
   * active encryption credentials, the active credentials with no specified usage are used instead. Revoked
   * credentials are never returned.
   * </p>
   *
   * @param filter a filter that the credentials must meet, for example a check of the key type
   * @return a (possibly empty) list of credentials
   */
  @Nonnull
  public List<PkiCredential> getCredentialsForEncryption(@Nonnull final Predicate<PkiCredential> filter) {
    Objects.requireNonNull(filter, "filter must not be null");
    final Instant now = this.clock.instant();
    final Predicate<PkiCredential> active = isActiveAt(now).and(filter);
    final Predicate<PkiCredential> noLongerActive = isNoLongerActiveAt(now).and(isRevokedAt(now).negate()).and(filter);

    final List<PkiCredential> result = new ArrayList<>(this.getSortedCredentials(encryptionUsage.and(active)));
    if (!result.isEmpty()) {
      // Add the previous encryption credentials ...
      result.addAll(this.getCredentials(encryptionUsage.and(noLongerActive)));
    }
    else {
      result.addAll(this.getSortedCredentials(unspecifiedUsage.and(active)));
      result.addAll(
          Optional.of(this.getCredentials(encryptionUsage.and(noLongerActive)))
              .filter(c -> !c.isEmpty())
              .orElseGet(() -> this.getCredentials(unspecifiedUsage.and(noLongerActive))));
    }
    return result;
  }

  /**
   * Gets the matching credential with the latest {@value PkiCredential.Metadata#ACTIVE_FROM_PROPERTY}.
   *
   * @param predicate the predicate
   * @return the credential, or an empty {@link Optional}
   */
  @Nonnull
  private Optional<PkiCredential> getLatestActive(@Nonnull final Predicate<PkiCredential> predicate) {
    return this.getSortedCredentials(predicate).stream().findFirst();
  }

  /**
   * Gets the matching credentials ordered so that the one with the latest
   * {@value PkiCredential.Metadata#ACTIVE_FROM_PROPERTY} comes first.
   *
   * @param predicate the predicate
   * @return a list of credentials
   */
  @Nonnull
  private List<PkiCredential> getSortedCredentials(@Nonnull final Predicate<PkiCredential> predicate) {
    return this.credentials.stream().filter(predicate).sorted(LATEST_ACTIVE_FROM_FIRST).toList();
  }

  /**
   * {@link Predicate} that tells whether a credential holds an RSA key.
   */
  public static final Predicate<PkiCredential> isRsa = c -> c.getPublicKey().getAlgorithm().equals("RSA");

  /**
   * {@link Predicate} that tells whether a credential holds an EC key.
   */
  public static final Predicate<PkiCredential> isEc = c -> c.getPublicKey().getAlgorithm().equals("EC");

  /**
   * {@link Predicate} that tells whether a credential is a hardware credential, i.e., stored on an HSM.
   */
  public static final Predicate<PkiCredential> isHardwareCredential = PkiCredential::isHardwareCredential;

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
  public static final Predicate<PkiCredential> signatureUsage = usage(PkiCredential.Metadata.USAGE_SIGNING);

  /**
   * {@link Predicate} that checks if the credential has the {@link PkiCredential.Metadata#USAGE_ENCRYPTION} usage.
   */
  public static final Predicate<PkiCredential> encryptionUsage = usage(PkiCredential.Metadata.USAGE_ENCRYPTION);

  /**
   * {@link Predicate} that checks if the credential does not have a specified usage.
   */
  public static final Predicate<PkiCredential> unspecifiedUsage = c -> c.getMetadata().getUsage() == null;

  /**
   * Method that returns a {@link Predicate} that checks if a credential is revoked at the given time, meaning that a
   * {@link PkiCredential.Metadata#REVOKED_AT_PROPERTY} setting is not after the given time.
   *
   * @param at the time to evaluate
   * @return a {@link Predicate}
   */
  public static Predicate<PkiCredential> isRevokedAt(@Nonnull final Instant at) {
    Objects.requireNonNull(at, "at must not be null");
    return c -> Optional.ofNullable(c.getMetadata().getRevokedAt())
        .filter(r -> !at.isBefore(r))
        .isPresent();
  }

  /**
   * Method that returns a {@link Predicate} that checks if a credential is "active" at the given time, meaning that the
   * time is within the {@link PkiCredential.Metadata#ACTIVE_FROM_PROPERTY} and
   * {@link PkiCredential.Metadata#ACTIVE_TO_PROPERTY} properties, and that the credential is not revoked. If no such
   * properties are set, the credential is active.
   *
   * @param at the time to evaluate
   * @return a {@link Predicate}
   */
  public static Predicate<PkiCredential> isActiveAt(@Nonnull final Instant at) {
    Objects.requireNonNull(at, "at must not be null");
    final Predicate<PkiCredential> revoked = isRevokedAt(at);
    return c -> {
      if (revoked.test(c)) {
        return false;
      }
      final Instant activeTo = c.getMetadata().getActiveTo();
      if (activeTo != null && at.isAfter(activeTo)) {
        return false;
      }
      final Instant activeFrom = c.getMetadata().getActiveFrom();
      return activeFrom == null || !at.isBefore(activeFrom);
    };
  }

  /**
   * Method that returns a {@link Predicate} that checks if a credential is no longer active at the given time, meaning
   * that a {@link PkiCredential.Metadata#ACTIVE_TO_PROPERTY} setting is before the given time, or that the credential
   * is revoked.
   *
   * @param at the time to evaluate
   * @return a {@link Predicate}
   */
  public static Predicate<PkiCredential> isNoLongerActiveAt(@Nonnull final Instant at) {
    Objects.requireNonNull(at, "at must not be null");
    return isRevokedAt(at).or(c -> Optional.ofNullable(c.getMetadata().getActiveTo())
        .map(at::isAfter)
        .orElse(false));
  }

  /**
   * Method that returns a {@link Predicate} that checks if a credential is "not yet active" at the given time, meaning
   * that the {@link PkiCredential.Metadata#ACTIVE_FROM_PROPERTY} setting is after the given time, and that the
   * credential is not revoked.
   *
   * @param at the time to evaluate
   * @return a {@link Predicate}
   */
  public static Predicate<PkiCredential> isNotYetActiveAt(@Nonnull final Instant at) {
    Objects.requireNonNull(at, "at must not be null");
    return isRevokedAt(at).negate().and(c -> Optional.ofNullable(c.getMetadata().getActiveFrom())
        .filter(at::isBefore)
        .isPresent());
  }

  /**
   * {@link Predicate} that checks if the credential is "active" at the current system time. See
   * {@link #isActiveAt(Instant)}.
   *
   * @deprecated Use {@link #isActiveAt(Instant)} or {@link #getActiveCredentials()}
   */
  @Deprecated(since = "2.4.0")
  public static final Predicate<PkiCredential> isActive = c -> isActiveAt(Instant.now()).test(c);

  /**
   * {@link Predicate} that checks if the credential is no longer active at the current system time. See
   * {@link #isNoLongerActiveAt(Instant)}.
   *
   * @deprecated Use {@link #isNoLongerActiveAt(Instant)} or {@link #getNoLongerActiveCredentials()}
   */
  @Deprecated(since = "2.4.0")
  public static final Predicate<PkiCredential> noLongerActive = c -> isNoLongerActiveAt(Instant.now()).test(c);

  /**
   * {@link Predicate} that tells whether the credential is "not yet active" at the current system time. See
   * {@link #isNotYetActiveAt(Instant)}.
   *
   * @deprecated Use {@link #isNotYetActiveAt(Instant)} or {@link #getNotYetActiveCredentials()}
   */
  @Deprecated(since = "2.4.0")
  public static final Predicate<PkiCredential> isNotYetActive = c -> isNotYetActiveAt(Instant.now()).test(c);

  /**
   * {@link Predicate} that tells if a credential is intended to be the signing credential in the future.
   *
   * @deprecated Use {@code signatureUsage.and(isNotYetActiveAt(instant))}
   */
  @Deprecated(since = "2.4.0")
  public static final Predicate<PkiCredential> forFutureSigning =
      c -> signatureUsage.and(isNotYetActiveAt(Instant.now())).test(c);

}
