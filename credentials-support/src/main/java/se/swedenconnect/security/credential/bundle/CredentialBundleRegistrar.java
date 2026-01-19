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

/**
 * Interface to be implemented for registering {@link java.security.KeyStore KeyStore} and
 * {@link se.swedenconnect.security.credential.PkiCredential PkiCredential} objects at a
 * {@link CredentialBundleRegistry}.
 *
 * @author Martin Lindström
 */
@FunctionalInterface
public interface CredentialBundleRegistrar {

  /**
   * Callback method for registering {@link java.security.KeyStore KeyStore} and
   * {@link se.swedenconnect.security.credential.PkiCredential PkiCredential} objects at a
   * {@link CredentialBundleRegistry}.
   *
   * @param registry the registry that accepts registrations
   * @throws IllegalArgumentException for invalid registration/configuration data
   */
  void register(@Nonnull final CredentialBundleRegistry registry) throws IllegalArgumentException;

}
