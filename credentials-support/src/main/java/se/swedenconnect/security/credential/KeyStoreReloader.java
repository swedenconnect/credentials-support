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
package se.swedenconnect.security.credential;

import jakarta.annotation.Nonnull;

import java.security.KeyStore;
import java.security.KeyStoreException;

/**
 * When a {@link se.swedenconnect.security.credential.KeyStoreCredential KeyStoreCredential} is used with an underlying
 * PKCS#11 {@link }KeyStore} the implementation may want to reload the {@link KeyStore}. This class provides this
 * function.
 *
 * @author Martin Lindström
 */
@FunctionalInterface
public interface KeyStoreReloader {

  /**
   * Reloads a (PKCS#11) {@link KeyStore}.
   *
   * @param keyStore the {@link KeyStore}
   * @throws KeyStoreException for error reloading the keystore
   */
  void reload(@Nonnull final KeyStore keyStore) throws KeyStoreException;
}
