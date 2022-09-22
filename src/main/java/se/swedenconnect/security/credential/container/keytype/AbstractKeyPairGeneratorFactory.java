/*
 * Copyright 2020-2022 Sweden Connect
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

import java.util.Objects;

/**
 * Abstract base class for {@link KeyPairGeneratorFactory}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public abstract class AbstractKeyPairGeneratorFactory implements KeyPairGeneratorFactory {

  /** The key type supported by this factory. */
  private final String keyType;

  /**
   * Constructor.
   *
   * @param keyType the supported key type (see {@link KeyGenType}).
   */
  public AbstractKeyPairGeneratorFactory(final String keyType) {
    this.keyType = Objects.requireNonNull(keyType, "keyType must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public boolean supports(final String keyType) {
    return this.keyType.equalsIgnoreCase(keyType);
  }

}
