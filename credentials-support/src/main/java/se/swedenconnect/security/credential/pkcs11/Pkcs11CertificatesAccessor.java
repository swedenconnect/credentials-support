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
import java.security.cert.X509Certificate;

/**
 * A functional interface for getting a reference to a certificate chain residing on a PKCS#11 device.
 *
 * @author Martin Lindström
 */
public interface Pkcs11CertificatesAccessor extends Pkcs11ObjectAccessor<X509Certificate[]> {

  /**
   * Gets the certificate chain for the alias. The entity certificate must be placed first in the resulting array.
   * <p>
   * For PKCS#11 devices where no certificate is present (it may be held outside of the device), {@code null} should be
   * returned.
   * </p>
   */
  @Nullable
  @Override
  X509Certificate[] get(@Nonnull final Provider provider, @Nonnull final String alias, @Nonnull final char[] pin)
      throws SecurityException;
}
