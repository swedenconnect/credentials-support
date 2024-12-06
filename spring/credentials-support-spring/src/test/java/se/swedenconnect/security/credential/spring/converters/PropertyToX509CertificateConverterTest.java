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

import java.io.IOException;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test cases for PropertyToX509CertificateConverter.
 *
 * @author Martin Lindström
 */
@ExtendWith(SpringExtension.class)
@Import(BaseTestConfiguration.class)
@TestPropertySource(locations = { "classpath:converters.properties" })
@EnableConfigurationProperties(ConvertersConfigurationProperties.class)
public class PropertyToX509CertificateConverterTest {

  @Autowired
  ApplicationContext context;

  @Autowired(required = false)
  PropertyToX509CertificateConverter propertyToX509CertificateConverter;

  @Autowired
  ConvertersConfigurationProperties properties;

  @Test
  void testConvert() {
    final PropertyToX509CertificateConverter converter = new PropertyToX509CertificateConverter();
    converter.setApplicationContext(this.context);

    final X509Certificate cert = converter.convert("classpath:rsa1.crt");
    assertNotNull(cert);
  }

  @Test
  void testConvertInline() throws IOException {
    final PropertyToX509CertificateConverter converter = new PropertyToX509CertificateConverter();
    converter.setApplicationContext(this.context);

    final String pem = new String((new ClassPathResource("rsa1.crt")).getInputStream().readAllBytes());
    final X509Certificate cert = converter.convert(pem);
    assertNotNull(cert);
  }

  @Test
  void testConvertIncompletePath() {
    final PropertyToX509CertificateConverter converter = new PropertyToX509CertificateConverter();
    converter.setApplicationContext(this.context);

    final X509Certificate cert = converter.convert("test/rsa1.crt");
    assertNotNull(cert);
  }

  @Test
  void testConvertFailed() {
    assertThrows(IllegalArgumentException.class, () -> {
      final PropertyToX509CertificateConverter converter = new PropertyToX509CertificateConverter();
      converter.setApplicationContext(this.context);

      converter.convert("classpath:not-found.crt");
    });
  }

  @Test
  void testConverterBean() {
    assertNotNull(this.propertyToX509CertificateConverter, "PropertyToX509CertificateConverter bean is not present");
    assertNotNull(this.propertyToX509CertificateConverter.convert("classpath:rsa1.crt"));
  }

  @Test
  void testCertIsPresent() {
    assertNotNull(this.properties.getCert());
  }

}
