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
package se.swedenconnect.security.credential.pkcs11;

import jakarta.annotation.Nonnull;

import java.security.PrivateKey;
import java.security.Provider;

/**
 * A functional interface for getting a reference to a private key residing on a PKCS#11 device.
 *
 * @author Martin Lindström
 */
public interface Pkcs11PrivateKeyAccessor extends Pkcs11ObjectAccessor<PrivateKey> {

  /**
   * Gets a reference to the private key from the PKCS#11 device, and throws {@link SecurityException} if it can not be
   * extracted or is not found.
   */
  @Nonnull
  @Override
  PrivateKey get(@Nonnull final Provider provider, @Nonnull final String alias, @Nonnull final char[] pin)
      throws SecurityException;
}
