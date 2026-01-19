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
package se.swedenconnect.security.credential.bundle;

import jakarta.annotation.Nonnull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.swedenconnect.security.credential.PkiCredential;

import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Default implementation of the {@link CredentialBundles} and {@link CredentialBundleRegistry} interfaces.
 *
 * @author Martin Lindström
 */
public class DefaultCredentialBundleRegistry implements CredentialBundleRegistry, CredentialBundles {

  /** Logger instance. */
  private static final Logger log = LoggerFactory.getLogger(DefaultCredentialBundleRegistry.class);

  /** The key stores. */
  private final Map<String, KeyStore> keyStores = new ConcurrentHashMap<>();

  /** The credentials. */
  private final Map<String, PkiCredential> credentials = new ConcurrentHashMap<>();

  /** {@inheritDoc} */
  @Override
  public void registerCredential(@Nonnull final String id, @Nonnull final PkiCredential credential)
      throws IllegalArgumentException {
    final PkiCredential previous = this.credentials.putIfAbsent(
        Objects.requireNonNull(id, "id must not be null"),
        Objects.requireNonNull(credential, "credential must not be null"));
    if (previous != null) {
      throw new IllegalArgumentException("A credential for '%s' has already been registered".formatted(id));
    }
    log.debug("Credential '{}' registered", id);
  }

  /** {@inheritDoc} */
  @Override
  public void registerKeyStore(@Nonnull final String id, @Nonnull final KeyStore keyStore) {
    final KeyStore previous = this.keyStores.putIfAbsent(
        Objects.requireNonNull(id, "id must not be null"),
        Objects.requireNonNull(keyStore, "keyStore must not be null"));
    if (previous != null) {
      throw new IllegalArgumentException("A key store for '%s' has already been registered".formatted(id));
    }
    log.debug("Key store '{}' registered", id);
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public PkiCredential getCredential(@Nonnull final String id) throws NoSuchCredentialException {
    final PkiCredential credential = this.credentials.get(Objects.requireNonNull(id, "id must not be null"));
    if (credential == null) {
      throw new NoSuchCredentialException(id, "Credential '%s' is not registered".formatted(id));
    }
    return credential;
  }

  /**
   * Gets a list of all ID:s for registered credentials.
   *
   * @return a list of all ID:s for registered credentials
   */
  @Override
  @Nonnull
  public List<String> getRegisteredCredentials() {
    return new ArrayList<>(this.credentials.keySet());
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public KeyStore getKeyStore(@Nonnull final String id) throws NoSuchKeyStoreException {
    final KeyStore keyStore = this.keyStores.get(Objects.requireNonNull(id, "id must not be null"));
    if (keyStore == null) {
      throw new NoSuchKeyStoreException(id, "Key store '%s' is not registered".formatted(id));
    }
    return keyStore;
  }

  /**
   * Gets a list of all ID:s for registered key stores.
   *
   * @return a list of all ID:s for registered key stores
   */
  @Override
  @Nonnull
  public List<String> getRegisteredKeyStores() {
    return new ArrayList<>(this.keyStores.keySet());
  }

}
