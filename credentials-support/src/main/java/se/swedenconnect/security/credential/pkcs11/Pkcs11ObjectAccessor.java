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
package se.swedenconnect.security.credential.pkcs11;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.security.Provider;

/**
 * A functional interface for getting a reference to an object residing on a PKCS#11 device.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@FunctionalInterface
public interface Pkcs11ObjectAccessor<T> {

  /**
   * Gets a reference to an object residing on the PKCS#11 device.
   *
   * @param provider the security provider to use
   * @param alias the alias to the entry holding the object
   * @param pin the PIN needed to access the entry
   * @return an object reference or {@code null} if the object is not available
   * @throws SecurityException if the operation is not successful
   */
  @Nullable
  T get(@Nonnull final Provider provider, @Nonnull final String alias, @Nonnull final char[] pin)
      throws SecurityException;

}
