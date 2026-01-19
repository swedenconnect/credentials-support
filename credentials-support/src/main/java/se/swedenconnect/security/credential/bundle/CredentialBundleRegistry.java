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
import se.swedenconnect.security.credential.PkiCredential;

import java.security.KeyStore;

/**
 * Interface for registering {@link PkiCredential}s and {@link KeyStore}s.
 *
 * @author Martin Lindström
 */
public interface CredentialBundleRegistry {

  /**
   * Registers a credential.
   *
   * @param id the unique credential ID
   * @param credential the {@link PkiCredential} to register
   * @throws IllegalArgumentException if another credential already has been registered under the given ID
   */
  void registerCredential(@Nonnull final String id, @Nonnull final PkiCredential credential)
      throws IllegalArgumentException;

  /**
   * Registers a key store.
   *
   * @param id the unique key store ID.
   * @param keyStore the {@link KeyStore} to register.
   * @throws IllegalArgumentException if another key store already has been registered under the given ID
   */
  void registerKeyStore(@Nonnull final String id, @Nonnull final KeyStore keyStore) throws IllegalArgumentException;

}
