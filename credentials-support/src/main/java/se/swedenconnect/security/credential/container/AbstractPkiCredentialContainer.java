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
package se.swedenconnect.security.credential.container;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.swedenconnect.security.credential.container.keytype.KeyGenType;
import se.swedenconnect.security.credential.container.keytype.KeyPairGeneratorFactory;
import se.swedenconnect.security.credential.container.keytype.KeyPairGeneratorFactoryRegistry;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Abstract implementation of the {@link PkiCredentialContainer} interface.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public abstract class AbstractPkiCredentialContainer implements PkiCredentialContainer {

  /** Logging instance. */
  private static final Logger log = LoggerFactory.getLogger(AbstractPkiCredentialContainer.class);

  /**
   * The key gen types (see {@link KeyGenType}) that are supported by default. To change this, use
   * {@link #setSupportedKeyTypes(List)}.
   */
  public static final String[] DEFAULT_SUPPORTED_KEY_TYPES = new String[] {
      KeyGenType.EC_P256,
      KeyGenType.EC_P384,
      KeyGenType.EC_P521,
      KeyGenType.RSA_3072,
      KeyGenType.RSA_4096
  };

  /** The provider for the key store where generated keys are stored. */
  private final Provider provider;

  /** The duration for which all generated keys are valid. */
  private Duration keyValidity = Duration.ofMinutes(15);

  /** List of supported key types. */
  private List<String> supportedKeyTypes;

  /** Random source for generating unique key aliases. */
  private final SecureRandom RNG = new SecureRandom();

  /**
   * Constructor.
   *
   * @param provider the provider that is used to create and manage keys
   */
  public AbstractPkiCredentialContainer(@Nonnull final Provider provider) {
    this.provider = Objects.requireNonNull(provider, "provider must not be null");
    this.supportedKeyTypes = Arrays.asList(DEFAULT_SUPPORTED_KEY_TYPES);
  }

  /**
   * Overridable function to generate the unique alias for each generated key.
   *
   * @return {@link BigInteger} key alias
   */
  @Nonnull
  protected BigInteger generateAlias() {
    return new BigInteger(64, this.RNG);
  }

  /** {@inheritDoc} */
  @Override
  public void cleanup() throws PkiCredentialContainerException {
    if (this.getKeyValidity() == null) {
      return;
    }

    final List<String> credentialAliasList = this.listCredentials();

    for (final String alias : credentialAliasList) {
      try {
        if (this.isExpired(alias)) {
          this.deleteCredential(alias);
        }
      }
      catch (final PkiCredentialContainerException e) {
        log.warn("Failed to clean up credential with alias '{}'", alias, e);
      }
    }
  }

  /**
   * Checks if the entry identified with {@code alias} is expired.
   *
   * @param alias the key entry alias
   * @return true if the entry has expired, and false otherwise
   * @throws PkiCredentialContainerException for errors getting the entry
   */
  protected boolean isExpired(@Nonnull final String alias) throws PkiCredentialContainerException {
    final Instant expires = this.getExpiryTime(alias);
    if (expires == null) {
      return false;
    }
    return expires.isBefore(Instant.now());
  }

  /**
   * Assigns the duration for the validity of generated credentials.
   * <p>
   * If supplied with {@code null} the generated key pairs will never expire. In these cases each generated credential
   * must be manually deleted using {@link #deleteCredential(String)}.
   * </p>
   *
   * @param keyValidity the validity
   */
  @Override
  public void setKeyValidity(@Nullable final Duration keyValidity) {
    this.keyValidity = keyValidity;
  }

  /**
   * Gets the key validity. A value of {@code null} means that credentials never expire.
   *
   * @return the validity, or null
   */
  @Nullable
  protected Duration getKeyValidity() {
    return this.keyValidity;
  }

  /**
   * Assigns the key types that this container supports. The default is {@link #DEFAULT_SUPPORTED_KEY_TYPES}.
   *
   * @param supportedKeyTypes a list of supported key types
   */
  @Override
  public void setSupportedKeyTypes(@Nonnull final List<String> supportedKeyTypes) {
    this.supportedKeyTypes = Optional.ofNullable(supportedKeyTypes)
        .filter(s -> !s.isEmpty())
        .orElseThrow(() -> new IllegalArgumentException("supportedKeyTypes must not be null or empty"));
  }

  /**
   * Gets the security provider used by the container.
   *
   * @return the provider
   */
  @Nonnull
  protected Provider getProvider() {
    return this.provider;
  }

  /**
   * Gets a {@link KeyPairGeneratorFactory} that can be used to generate key pairs given the supplied
   * {@code keyTypeName}.
   *
   * @param keyTypeName the key type name
   * @return a KeyPairGeneratorFactory
   * @throws NoSuchAlgorithmException if no match is found
   */
  @Nonnull
  protected KeyPairGeneratorFactory getKeyGeneratorFactory(@Nonnull final String keyTypeName)
      throws NoSuchAlgorithmException {
    try {
      return this.supportedKeyTypes.stream()
          .filter(t -> t.equalsIgnoreCase(keyTypeName))
          .map(KeyPairGeneratorFactoryRegistry::getFactory)
          .findFirst()
          .orElseThrow(
              () -> new NoSuchAlgorithmException("%s is not supported by this container".formatted(keyTypeName)));
    }
    catch (final IllegalArgumentException e) {
      throw new NoSuchAlgorithmException("No matching key generation factory found for " + keyTypeName);
    }
  }

}
