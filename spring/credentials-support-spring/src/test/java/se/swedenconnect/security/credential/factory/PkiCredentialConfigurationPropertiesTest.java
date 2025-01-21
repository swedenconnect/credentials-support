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
package se.swedenconnect.security.credential.factory;

import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import se.swedenconnect.security.credential.utils.X509Utils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test cases for the deprecated {@link PkiCredentialConfigurationProperties} class.
 *
 * @author Martin Lindström
 */
public class PkiCredentialConfigurationPropertiesTest {

  @Test
  void testPemMultipleCerts() {
    final PkiCredentialConfigurationProperties props = new PkiCredentialConfigurationProperties();
    props.setCertificates(List.of(new ClassPathResource("rsa1.crt"), new ClassPathResource("rsa1.crt")));
    props.setPrivateKey(new ClassPathResource("rsa1.pkcs8.key"));
    props.setName("test");
    props.afterPropertiesSet();

    assertNotNull(props.getPem());
    assertNotNull(props.getPem().getPrivateKey());
    assertNotNull(props.getPem().getCertificates());
    assertTrue(X509Utils.isInlinedPem(props.getPem().getCertificates()));
    assertNotNull(props.getPem().getName());

    assertFalse(props.hasDeprecatedProperties());
  }

  @Test
  void testPemSingleCert() {
    final PkiCredentialConfigurationProperties props = new PkiCredentialConfigurationProperties();
    props.setCertificate(new ClassPathResource("rsa1.crt"));
    props.setPrivateKey(new ClassPathResource("rsa1.pkcs8.key"));
    props.setName("test");
    props.afterPropertiesSet();

    assertNotNull(props.getPem());
    assertNotNull(props.getPem().getPrivateKey());
    assertNotNull(props.getPem().getCertificates());
    assertFalse(X509Utils.isInlinedPem(props.getPem().getCertificates()));
    assertNotNull(props.getPem().getName());

    assertFalse(props.hasDeprecatedProperties());
  }

}
