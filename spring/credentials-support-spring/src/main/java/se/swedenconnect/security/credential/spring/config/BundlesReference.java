/*
 * Copyright 2020-2025 Sweden Connect
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

import java.util.function.Supplier;

/**
 * Base interface for references to objects declared in a
 * {@link se.swedenconnect.security.credential.bundle.CredentialBundles CredentialBundles}.
 *
 * @author Martin Lindström
 */
@FunctionalInterface
public interface BundlesReference<T> extends Supplier<T> {

  /**
   * Resolves the object by invoking the underlying
   * {@link se.swedenconnect.security.credential.bundle.CredentialBundles CredentialBundles} bean.
   * <p>
   * Throws a {@link RuntimeException} if no object is available.
   * </p>
   *
   * @return the object
   */
  @Nonnull
  T get();
}
