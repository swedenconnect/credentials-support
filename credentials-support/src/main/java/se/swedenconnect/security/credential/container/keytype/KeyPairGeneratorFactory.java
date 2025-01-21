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
package se.swedenconnect.security.credential.container.keytype;

import jakarta.annotation.Nonnull;

import java.security.KeyException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

/**
 * Intarface for a factory for creating a {@link KeyPairGenerator} suitable for a specific key type.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface KeyPairGeneratorFactory {

  /**
   * Creates a key pair generator.
   *
   * @param provider the crypto provider used to create the key pair generator
   * @return a {@link KeyPairGenerator}
   * @throws NoSuchAlgorithmException the key type served by this factory instance is not supported by the specified
   *           provider
   * @throws KeyException error initiating the key pair generator
   */
  @Nonnull
  KeyPairGenerator getKeyPairGenerator(@Nonnull final Provider provider) throws NoSuchAlgorithmException, KeyException;

  /**
   * Predicate telling whether this factory instance supports a particular key type (see {@link KeyGenType}).
   *
   * @param keyType the requested key type name
   * @return true if this factory instance supports the specified key type and false otherwise
   */
  boolean supports(@Nonnull final String keyType);

}
