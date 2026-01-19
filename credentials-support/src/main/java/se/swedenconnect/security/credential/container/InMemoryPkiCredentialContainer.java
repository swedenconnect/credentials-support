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
package se.swedenconnect.security.credential.container;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.PkiCredential;

import java.security.KeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * An in-memory implementation of the {@link PkiCredentialContainer} interface.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class InMemoryPkiCredentialContainer extends AbstractPkiCredentialContainer {

  /** The credentials for this container. */
  private final Map<String, ExtendedBasicCredential> credentials = new ConcurrentHashMap<>();

  /**
   * Constructor loading the security provider identified by {@code providerName}.
   *
   * @param providerName the name of the security provider
   */
  public InMemoryPkiCredentialContainer(@Nonnull final String providerName) {
    super(Security.getProvider(providerName));
  }

  /**
   * Constructor.
   *
   * @param provider the provider that is used to create and manage keys
   */
  public InMemoryPkiCredentialContainer(@Nonnull final Provider provider) {
    super(provider);
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String generateCredential(@Nonnull final String keyTypeName)
      throws KeyException, NoSuchAlgorithmException {

    final KeyPairGenerator keyPairGenerator =
        this.getKeyGeneratorFactory(keyTypeName).getKeyPairGenerator(this.getProvider());
    final KeyPair keyPair = keyPairGenerator.generateKeyPair();
    final String alias = this.generateAlias().toString(16);
    try {
      final ExtendedBasicCredential credential = new ExtendedBasicCredential(keyPair, alias, this.getKeyValidity());
      this.credentials.put(alias, credential);
      return alias;
    }
    catch (final Exception e) {
      throw new KeyException("Failed to initialize credential", e);
    }
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public ManagedPkiCredential getCredential(@Nonnull final String alias) throws PkiCredentialContainerException {
    final PkiCredential credential = this.credentials.get(alias);
    if (credential == null) {
      throw new PkiCredentialContainerException(String.format("Credential with alias '%s' was not found", alias));
    }
    if (this.isExpired(alias)) {
      this.deleteCredential(alias);
      throw new PkiCredentialContainerException("Requested credential has expired - Destroying credential");
    }
    return new ManagedPkiCredential(credential, c -> this.deleteCredential(alias), null);
  }

  /** {@inheritDoc} */
  @Override
  public void deleteCredential(@Nonnull final String alias) {
    this.credentials.remove(alias);
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public Instant getExpiryTime(@Nonnull final String alias) throws PkiCredentialContainerException {
    final ExtendedBasicCredential credential = Optional.ofNullable(this.credentials.get(alias))
        .orElseThrow(
            () -> new PkiCredentialContainerException("Credential with alias '%s' was not found".formatted(alias)));
    return credential.getExpiryTime();
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public List<String> listCredentials() {
    return this.credentials.keySet().stream().toList();
  }

  /**
   * A wrapper of {@link BasicCredential} that also includes expiration time.
   *
   * @author Martin Lindström (martin@idsec.se)
   * @author Stefan Santesson (stefan@idsec.se)
   */
  private static class ExtendedBasicCredential extends BasicCredential {

    /** The expiry time. */
    private final Instant validTo;

    /**
     * Constructor.
     *
     * @param keyPair the key pair
     * @param alias the alias for this credential
     * @param validity the key validity (may be null)
     */
    public ExtendedBasicCredential(
        @Nonnull final KeyPair keyPair, @Nonnull final String alias, @Nullable final Duration validity) {
      super(keyPair);
      super.setName(alias);
      this.validTo = validity != null ? Instant.now().plusMillis(validity.toMillis()) : null;
    }

    /**
     * Gets the expiry time of the credential.
     *
     * @return expiry time for the credential or null if the credential never expires
     */
    public Instant getExpiryTime() {
      return this.validTo;
    }

    /**
     * Blocked from usage. The name is hard-wired to the alias.
     */
    @Override
    public void setName(@Nonnull final String name) {
      throw new IllegalArgumentException("The credential name can not be set");
    }

  }

}
