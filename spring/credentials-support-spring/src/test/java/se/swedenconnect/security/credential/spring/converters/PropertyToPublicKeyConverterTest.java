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
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import se.swedenconnect.security.credential.spring.BaseTestConfiguration;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test cases for PropertyToPublicKeyConverter.
 *
 * @author Martin Lindström
 */
@ExtendWith(SpringExtension.class)
@Import(BaseTestConfiguration.class)
@TestPropertySource(locations = { "classpath:converters.properties" })
@EnableConfigurationProperties(ConvertersConfigurationProperties.class)
public class PropertyToPublicKeyConverterTest {

  @Autowired
  ApplicationContext context;

  @Autowired(required = false)
  PropertyToPublicKeyConverter propertyToPublicKeyConverter;

  @Autowired
  ConvertersConfigurationProperties properties;

  @Test
  void testConvert() {
    final PropertyToPublicKeyConverter converter = new PropertyToPublicKeyConverter();
    converter.setApplicationContext(this.context);

    final PublicKey pk = converter.convert("classpath:rsa1.pubkey.der");
    assertNotNull(pk);
    assertNotNull(converter.convert("classpath:ec.pubkey.pem"));
  }

  @Test
  void testConvertNoPath() {
    final PropertyToPublicKeyConverter converter = new PropertyToPublicKeyConverter();
    converter.setApplicationContext(this.context);

    final PublicKey pk = converter.convert("ec.pubkey.pem");
    assertNotNull(pk);
  }

  @Test
  void testConvertInlinePem() throws IOException {
    final PropertyToPublicKeyConverter converter = new PropertyToPublicKeyConverter();
    converter.setApplicationContext(this.context);

    final String pem = new String((new ClassPathResource("ec.pubkey.pem")).getInputStream().readAllBytes());
    final PublicKey pk = converter.convert(pem);
    assertNotNull(pk);
  }

  @Test
  void testConvertFilePath() throws Exception {
    final PropertyToPublicKeyConverter converter = new PropertyToPublicKeyConverter();
    converter.setApplicationContext(this.context);

    final String fullPath = (new ClassPathResource("ec.pubkey.pem")).getFile().getAbsolutePath();

    final PublicKey pk = converter.convert(fullPath);
    assertNotNull(pk);

    final PublicKey pk2 = converter.convert("file:" + fullPath);
    assertNotNull(pk2);
  }

  @Test
  void testConvertFailed() {

    assertThrows(IllegalArgumentException.class, () -> {
      final PropertyToPublicKeyConverter converter = new PropertyToPublicKeyConverter();
      converter.setApplicationContext(this.context);

      converter.convert("classpath:not-found.key");
    });

  }

  @Test
  void testConverterBean() {
    assertNotNull(this.propertyToPublicKeyConverter, "PropertyToPublicKeyConverter bean is not present");
    assertNotNull(this.propertyToPublicKeyConverter.convert("classpath:rsa1.pubkey.der"));
  }

  @Test
  void testSpringContextPrivateKeysSet() {
    assertNotNull(this.properties.getPublicKey());
    assertNotNull(this.properties.getPublicKey2());
  }

}
