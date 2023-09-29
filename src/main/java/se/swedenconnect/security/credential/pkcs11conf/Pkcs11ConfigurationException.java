/*
 * Copyright 2020-2023 Sweden Connect
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
package se.swedenconnect.security.credential.pkcs11conf;

/**
 * Exception class for reporting invalid PKCS#11 configuration or failures to instatiate a PKCS#11 provider.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class Pkcs11ConfigurationException extends SecurityException {

  /** For serialization. */
  private static final long serialVersionUID = 4753744976030288668L;

  /**
   * Constructor setting the error message.
   *
   * @param message
   *          the error message
   */
  public Pkcs11ConfigurationException(final String message) {
    super(message);
  }

  /**
   * Constructor setting the error message and the cause of the error.
   *
   * @param message
   *          the error message
   * @param cause
   *          the cause of the error
   */
  public Pkcs11ConfigurationException(final String message, final Throwable cause) {
    super(message, cause);
  }

}
