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

import jakarta.annotation.Nullable;

import java.util.function.Supplier;

/**
 * An interface for credentials are "testable" and "reloadable".
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface ReloadablePkiCredential extends PkiCredential {

  /**
   * A credential may be monitored to ensure that it is functional. This can be useful when using for example
   * credentials residing on hardware devices where the connection may be lost. If a credential implementation should be
   * "testable" it must return a function for testing itself. This function ({@link Supplier}) returns an
   * {@link Exception} for test failures and {@code null} for success.
   * <p>
   * A credential that returns a function should also implement the {@link #reload()} method.
   * </p>
   *
   * @return a function for testing the credential, or {@code null} if no test function is available
   */
  @Nullable
  Supplier<Exception> getTestFunction();

  /**
   * Some implementations of key pairs, such as HSM-based, may need to be reloaded. This is done by implementing this
   * method.
   *
   * @throws Exception for reloading errors
   */
  void reload() throws Exception;

}
