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
package se.swedenconnect.security.credential.spring.config;

import jakarta.annotation.Nonnull;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.bundle.NoSuchCredentialException;

/**
 * A {@link se.swedenconnect.security.credential.bundle.CredentialBundles CredentialBundles} reference to a
 * {@link PkiCredential}.
 *
 * @author Martin Lindström
 */
@FunctionalInterface
public interface PkiCredentialReference extends BundlesReference<PkiCredential> {

  /**
   * Resolves a reference to a {@link PkiCredential} using the
   * {@link se.swedenconnect.security.credential.bundle.CredentialBundles CredentialBundles} bean.
   *
   * @return a {@link PkiCredential}
   * @throws NoSuchCredentialException if no such credential exists
   */
  @Nonnull
  @Override
  PkiCredential get() throws NoSuchCredentialException;
}
