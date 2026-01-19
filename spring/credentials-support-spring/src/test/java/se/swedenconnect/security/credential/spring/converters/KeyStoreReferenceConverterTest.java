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
package se.swedenconnect.security.credential.spring.converters;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.springframework.context.ApplicationContext;
import se.swedenconnect.security.credential.bundle.CredentialBundles;
import se.swedenconnect.security.credential.bundle.NoSuchKeyStoreException;

import java.security.KeyStore;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test cases for KeyStoreReferenceConverter.
 *
 * @author Martin Lindström
 */
class KeyStoreReferenceConverterTest {

  @Test
  void testConvert() {
    final CredentialBundles bundles = mock(CredentialBundles.class);
    when(bundles.getKeyStore(ArgumentMatchers.eq("test1"))).thenReturn(mock(KeyStore.class));
    when(bundles.getKeyStore(ArgumentMatchers.eq("test2"))).thenThrow(
        new NoSuchKeyStoreException("test2", "No such key store"));

    final ApplicationContext applicationContext = mock(ApplicationContext.class);
    when(applicationContext.getBean(ArgumentMatchers.eq(CredentialBundles.class))).thenReturn(bundles);

    final KeyStoreReferenceConverter converter = new KeyStoreReferenceConverter();
    converter.setApplicationContext(applicationContext);

    assertNotNull(converter.convert("test1").get());
    assertThrows(NoSuchKeyStoreException.class, () -> converter.convert("test2").get());
  }

}
