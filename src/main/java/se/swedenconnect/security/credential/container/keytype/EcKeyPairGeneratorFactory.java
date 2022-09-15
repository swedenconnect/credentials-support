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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;

/**
 * Factory for elliptic curve key pair generators.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class EcKeyPairGeneratorFactory extends AbstractKeyPairGeneratorFactory {

  /** Algorithm parameter specification for the elliptic curve to generate. */
  private final AlgorithmParameterSpec algorithmParameterSpec;

  /**
   * Constructor for the Elliptic curve key pair generator factory.
   *
   * @param keyTypeName the name of the key type associated with this key pair generator factory
   * @param algorithmParameterSpec algorithm specification for the specified key type
   */
  public EcKeyPairGeneratorFactory(final String keyTypeName, final AlgorithmParameterSpec algorithmParameterSpec) {
    super(keyTypeName);
    this.algorithmParameterSpec =
        Objects.requireNonNull(algorithmParameterSpec, "algorithmParameterSpec must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public KeyPairGenerator getKeyPairGenerator(final Provider provider)
      throws NoSuchAlgorithmException, KeyException {

    final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", provider);
    try {
      keyPairGenerator.initialize(this.algorithmParameterSpec);
    }
    catch (final InvalidAlgorithmParameterException e) {
      throw new KeyException(e);
    }
    return keyPairGenerator;
  }
}
