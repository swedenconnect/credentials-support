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
package se.swedenconnect.security.credential.bundle;

import jakarta.annotation.Nonnull;
import se.swedenconnect.security.credential.PkiCredential;

import java.security.KeyStore;
import java.util.List;
import java.util.function.Function;

/**
 * An interface for accessing registered credentials and key stores.
 *
 * @author Martin Lindström
 */
public interface CredentialBundles {

  /**
   * Gets the {@link PkiCredential} registered under the given ID.
   *
   * @param id the unique credential ID
   * @return a {@link PkiCredential}
   * @throws NoSuchCredentialException if no credential is registered under the given ID
   */
  @Nonnull
  PkiCredential getCredential(@Nonnull final String id) throws NoSuchCredentialException;

  /**
   * Gets a function that provides a credential based on an identifier.
   *
   * @return a function to resolve a {@link PkiCredential} based on a supplied identifier
   */
  @Nonnull
  default Function<String, PkiCredential> getCredentialProvider() {
    return id -> {
      try {
        return this.getCredential(id);
      }
      catch (final NoSuchCredentialException e) {
        return null;
      }
    };
  }

  /**
   * Gets a list of all ID:s for registered credentials.
   *
   * @return a list of all ID:s for registered credentials
   */
  @Nonnull
  List<String> getRegisteredCredentials();

  /**
   * Gets the {@link KeyStore} registered under the given ID.
   *
   * @param id the unique key store ID
   * @return a {@link KeyStore}
   * @throws NoSuchKeyStoreException if no key store is registered under the given ID
   */
  @Nonnull
  KeyStore getKeyStore(@Nonnull final String id) throws NoSuchKeyStoreException;

  /**
   * Gets a function that provides a key store based on an identifier.
   *
   * @return a function to resolve a {@link KeyStore} based on a supplied identifier
   */
  @Nonnull
  default Function<String, KeyStore> getKeyStoreProvider() {
    return id -> {
      try {
        return this.getKeyStore(id);
      }
      catch (final NoSuchKeyStoreException e) {
        return null;
      }
    };
  }

  /**
   * Gets a list of all ID:s for registered key stores.
   *
   * @return a list of all ID:s for registered key stores
   */
  @Nonnull
  List<String> getRegisteredKeyStores();

}
