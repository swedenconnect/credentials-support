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

import java.security.PrivateKey;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test cases for PropertyToPrivateKeyConverter.
 *
 * @author Martin Lindström
 */
@ExtendWith(SpringExtension.class)
@Import(BaseTestConfiguration.class)
@TestPropertySource(locations = { "classpath:converters.properties" })
@EnableConfigurationProperties(ConvertersConfigurationProperties.class)
public class PropertyToPrivateKeyConverterTest {

  @Autowired
  ApplicationContext context;

  @Autowired(required = false)
  PropertyToPrivateKeyConverter propertyToPrivateKeyConverter;

  @Autowired
  ConvertersConfigurationProperties properties;

  @Test
  void testConvert() {
    final PropertyToPrivateKeyConverter converter = new PropertyToPrivateKeyConverter();
    converter.setApplicationContext(this.context);

    final PrivateKey pk = converter.convert("classpath:rsa1.pkcs8.key");
    assertNotNull(pk);
  }

  @Test
  void testConvertNoPath() {
    final PropertyToPrivateKeyConverter converter = new PropertyToPrivateKeyConverter();
    converter.setApplicationContext(this.context);

    final PrivateKey pk = converter.convert("rsa1.pkcs8.key");
    assertNotNull(pk);
  }

  @Test
  void testConvertFilePath() throws Exception {
    final PropertyToPrivateKeyConverter converter = new PropertyToPrivateKeyConverter();
    converter.setApplicationContext(this.context);

    final String fullPath = (new ClassPathResource("rsa1.pkcs8.key")).getFile().getAbsolutePath();

    final PrivateKey pk = converter.convert(fullPath);
    assertNotNull(pk);

    final PrivateKey pk2 = converter.convert("file:" + fullPath);
    assertNotNull(pk2);
  }

  @Test
  void testConvertFailed() {

    assertThrows(IllegalArgumentException.class, () -> {
      final PropertyToPrivateKeyConverter converter = new PropertyToPrivateKeyConverter();
      converter.setApplicationContext(this.context);

      converter.convert("classpath:not-found.key");
    });

  }

  @Test
  void testConverterBean() {
    assertNotNull(this.propertyToPrivateKeyConverter, "PropertyToPrivateKeyConverter bean is not present");
    assertNotNull(this.propertyToPrivateKeyConverter.convert("classpath:rsa1.pkcs8.key"));
  }

  @Test
  void testSpringContextPrivateKeysSet() {
    assertNotNull(this.properties.getOpensslKey());
    assertNotNull(this.properties.getPkcs8Key());
  }

}
