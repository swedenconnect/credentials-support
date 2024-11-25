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
package se.swedenconnect.security.credential.container.keytype;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

/**
 * Factory for RSA key pair generators.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class RsaKeyPairGeneratorFactory extends AbstractKeyPairGeneratorFactory {

  /** Key size for the generated RSA key */
  private final int keySize;

  /**
   * Constructor for the RSA key pair generator factory
   *
   * @param keyTypeName the name of the key type associated with this key pair generator factory
   * @param keySize key size of generated RSA keys
   */
  public RsaKeyPairGeneratorFactory(final String keyTypeName, final int keySize) {
    super(keyTypeName);
    this.keySize = keySize;
  }

  /** {@inheritDoc} */
  @Override
  public KeyPairGenerator getKeyPairGenerator(final Provider provider) throws NoSuchAlgorithmException {
    final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", provider);
    keyPairGenerator.initialize(this.keySize);
    return keyPairGenerator;
  }

}
