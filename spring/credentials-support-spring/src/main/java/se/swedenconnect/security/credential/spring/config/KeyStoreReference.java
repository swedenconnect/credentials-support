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
package se.swedenconnect.security.credential.spring.config;

import jakarta.annotation.Nonnull;
import se.swedenconnect.security.credential.bundle.NoSuchKeyStoreException;

import java.security.KeyStore;

/**
 * A {@link se.swedenconnect.security.credential.bundle.CredentialBundles CredentialBundles} reference to a
 * {@link KeyStore}.
 *
 * @author Martin Lindström
 */
@FunctionalInterface
public interface KeyStoreReference extends BundlesReference<KeyStore> {

  /**
   * Resolves a reference to a {@link KeyStore} using the
   * {@link se.swedenconnect.security.credential.bundle.CredentialBundles CredentialBundles} bean.
   *
   * @return a {@link KeyStore}
   * @throws NoSuchKeyStoreException if no such store exists
   */
  @Nonnull
  @Override
  KeyStore get() throws NoSuchKeyStoreException;
}
