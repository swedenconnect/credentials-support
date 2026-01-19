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
package se.swedenconnect.security.credential.factory;

import org.junit.jupiter.api.Test;
import se.swedenconnect.security.credential.config.DefaultConfigurationResourceLoader;
import se.swedenconnect.security.credential.pkcs11.MockSunPkcs11Provider;

import java.security.KeyStore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test cases for KeyStoreBuilder.
 *
 * @author Martin Lindström
 */
class KeyStoreBuilderTest {

  @Test
  void testBuildSoftwareBased() throws Exception {
    final KeyStore keyStore = KeyStoreBuilder.builder()
        .location("classpath:rsa1.jks")
        .password("secret")
        .build();
    assertNotNull(keyStore);

    // The same with all possible parameters ...
    final KeyStore keyStore2 = KeyStoreBuilder.builder()
        .location("classpath:rsa1.jks")
        .password("secret")
        .type("JKS")
        .provider(keyStore.getProvider().getName())
        .build();
    assertNotNull(keyStore2);
  }

  @Test
  void testMissingPassword() throws Exception {
    final IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> KeyStoreBuilder.builder()
        .location("classpath:rsa1.jks")
        .build());
    assertEquals("Missing password/pin", ex.getMessage());
  }

  @Test
  void testMissingLocation() throws Exception {
    final IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> KeyStoreBuilder.builder()
        .password("secret")
        .build());
    assertEquals("Missing location", ex.getMessage());
  }

  @Test
  void testPkcs11File() throws Exception {
    KeyStoreFactoryTest.setupPkcs11();
    try {
      final KeyStore keyStore = KeyStoreBuilder.builder(new DefaultConfigurationResourceLoader())
          .type("PKCS11")
          .provider(MockSunPkcs11Provider.PROVIDER_BASE_NAME)
          .pin("secret")
          .pkcs11ConfigurationFile(KeyStoreFactoryTest.getAbsolutePath("cfg1.txt"))
          .build();
      assertNotNull(keyStore);
      assertTrue(keyStore.getProvider().getName().startsWith(MockSunPkcs11Provider.PROVIDER_BASE_NAME));
    }
    finally {
      KeyStoreFactoryTest.tearDownPkcs11();
    }
  }

  @Test
  void testPkcs11PreConfiguredProvider() throws Exception {
    KeyStoreFactoryTest.setupPkcs11();
    try {
      final KeyStore _keyStore = KeyStoreBuilder.builder(new DefaultConfigurationResourceLoader())
          .type("PKCS11")
          .provider(MockSunPkcs11Provider.PROVIDER_BASE_NAME)
          .pin("secret")
          .pkcs11ConfigurationFile(KeyStoreFactoryTest.getAbsolutePath("cfg1.txt"))
          .build();

      final KeyStore keyStore = KeyStoreBuilder.builder()
          .type("PKCS11")
          .provider(_keyStore.getProvider().getName())
          .pin("secret")
          .build();
      assertNotNull(keyStore);
      assertEquals(_keyStore.getProvider().getName(), keyStore.getProvider().getName());
    }
    finally {
      KeyStoreFactoryTest.tearDownPkcs11();
    }
  }

  @Test
  void testPkcs11CustomParameters() throws Exception {
    KeyStoreFactoryTest.setupPkcs11();
    try {
      final KeyStore keyStore = KeyStoreBuilder.builder(new DefaultConfigurationResourceLoader())
          .type("PKCS11")
          .provider(MockSunPkcs11Provider.PROVIDER_BASE_NAME)
          .pin("secret")
          .pkcs11Library("/opt/foo/lib/libpkcs11.so")
          .pkcs11SlotName("Foo")
          .pkcs11Slot("S")
          .pkcs11SlotListIndex(1)
          .build();
      assertNotNull(keyStore);
      assertEquals(MockSunPkcs11Provider.PROVIDER_BASE_NAME + "-Foo", keyStore.getProvider().getName());
    }
    finally {
      KeyStoreFactoryTest.tearDownPkcs11();
    }
  }

}
