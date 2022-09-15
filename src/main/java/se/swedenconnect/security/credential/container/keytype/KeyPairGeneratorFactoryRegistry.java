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

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * A registry for getting a {@link KeyPairGeneratorFactory} based on a key type (see {@link KeyGenType}).
 * <p>
 * The registry supports all key gen types listed in {@link KeyGenType} by default. In order to support any other type,
 * use {@link #registerFactory(String, KeyPairGeneratorFactory)}.
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class KeyPairGeneratorFactoryRegistry {

  /** The registry (cache) of factories that have been created. */
  private static Map<String, KeyPairGeneratorFactory> registry = new HashMap<>();

  /**
   * Gets a {@link KeyPairGeneratorFactory} instance that can be used for creating key pairs corresponding to the
   * supplied {@code keyGenType} (see {@link KeyGenType}).
   *
   * @param keyGenType the key type
   * @return a KeyPairGeneratorFactory
   * @throws IllegalArgumentException if no factory is found
   */
  public static KeyPairGeneratorFactory getFactory(final String keyGenType) throws IllegalArgumentException {
    if (registry.containsKey(keyGenType)) {
      return registry.get(keyGenType);
    }
    KeyPairGeneratorFactory factory = null;
    if (KeyGenType.RSA_2048.equalsIgnoreCase(keyGenType)) {
      factory = new RsaKeyPairGeneratorFactory(KeyGenType.RSA_2048, 2048);
    }
    else if (KeyGenType.RSA_3072.equalsIgnoreCase(keyGenType)) {
      factory = new RsaKeyPairGeneratorFactory(KeyGenType.RSA_3072, 3072);
    }
    else if (KeyGenType.RSA_4096.equalsIgnoreCase(keyGenType)) {
      factory = new RsaKeyPairGeneratorFactory(KeyGenType.RSA_4096, 4096);
    }
    else if (KeyGenType.EC_P192.equalsIgnoreCase(keyGenType)) {
      factory = new EcKeyPairGeneratorFactory(KeyGenType.EC_P192, ECParameterSpecs.NIST_P192);
    }
    else if (KeyGenType.EC_P224.equalsIgnoreCase(keyGenType)) {
      factory = new EcKeyPairGeneratorFactory(KeyGenType.EC_P224, ECParameterSpecs.NIST_P224);
    }
    else if (KeyGenType.EC_P256.equalsIgnoreCase(keyGenType)) {
      factory = new EcKeyPairGeneratorFactory(KeyGenType.EC_P256, ECParameterSpecs.NIST_P256);
    }
    else if (KeyGenType.EC_P384.equalsIgnoreCase(keyGenType)) {
      factory = new EcKeyPairGeneratorFactory(KeyGenType.EC_P384, ECParameterSpecs.NIST_P384);
    }
    else if (KeyGenType.EC_P521.equalsIgnoreCase(keyGenType)) {
      factory = new EcKeyPairGeneratorFactory(KeyGenType.EC_P521, ECParameterSpecs.NIST_P521);
    }
    else if (KeyGenType.EC_BRAINPOOL_192.equalsIgnoreCase(keyGenType)) {
      factory = new EcKeyPairGeneratorFactory(KeyGenType.EC_BRAINPOOL_192, ECParameterSpecs.BRAINPOOL_P192R1);
    }
    else if (KeyGenType.EC_BRAINPOOL_224.equalsIgnoreCase(keyGenType)) {
      factory = new EcKeyPairGeneratorFactory(KeyGenType.EC_BRAINPOOL_224, ECParameterSpecs.BRAINPOOL_P224R1);
    }
    else if (KeyGenType.EC_BRAINPOOL_256.equalsIgnoreCase(keyGenType)) {
      factory = new EcKeyPairGeneratorFactory(KeyGenType.EC_BRAINPOOL_256, ECParameterSpecs.BRAINPOOL_P256R1);
    }
    else if (KeyGenType.EC_BRAINPOOL_320.equalsIgnoreCase(keyGenType)) {
      factory = new EcKeyPairGeneratorFactory(KeyGenType.EC_BRAINPOOL_320, ECParameterSpecs.BRAINPOOL_P320R1);
    }
    else if (KeyGenType.EC_BRAINPOOL_384.equalsIgnoreCase(keyGenType)) {
      factory = new EcKeyPairGeneratorFactory(KeyGenType.EC_BRAINPOOL_384, ECParameterSpecs.BRAINPOOL_P384R1);
    }
    else if (KeyGenType.EC_BRAINPOOL_512.equalsIgnoreCase(keyGenType)) {
      factory = new EcKeyPairGeneratorFactory(KeyGenType.EC_BRAINPOOL_512, ECParameterSpecs.BRAINPOOL_P512R1);
    }
    else {
      throw new IllegalArgumentException("No KeyPairGeneratorFactory registered for " + keyGenType);
    }

    registerFactory(keyGenType, factory);
    return factory;
  }

  /**
   * Registers a factory for the given key gen type.
   * <p>
   * Factories for any of the types given in {@link KeyGenType} do not have to be explicitly registered.
   * </p>
   *
   * @param keyGenType the key gen type
   * @param factory the factory to register
   */
  public static void registerFactory(final String keyGenType, final KeyPairGeneratorFactory factory) {
    registry.put(Objects.requireNonNull(keyGenType), Objects.requireNonNull(factory));
  }

  // Hidden
  private KeyPairGeneratorFactoryRegistry() {
  }

}
