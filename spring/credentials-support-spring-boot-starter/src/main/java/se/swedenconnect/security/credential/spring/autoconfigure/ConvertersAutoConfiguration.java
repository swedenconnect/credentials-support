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
package se.swedenconnect.security.credential.spring.autoconfigure;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;
import org.springframework.context.annotation.Bean;
import se.swedenconnect.security.credential.spring.converters.KeyStoreReferenceConverter;
import se.swedenconnect.security.credential.spring.converters.PkiCredentialReferenceConverter;
import se.swedenconnect.security.credential.spring.converters.PropertyToPrivateKeyConverter;
import se.swedenconnect.security.credential.spring.converters.PropertyToPublicKeyConverter;
import se.swedenconnect.security.credential.spring.converters.PropertyToX509CertificateConverter;

/**
 * Autoconfiguration for converters used for configuring credentials.
 *
 * @author Martin Lindström
 */
@AutoConfiguration
public class ConvertersAutoConfiguration {

  /**
   * Creates the bean the allows us to use property values that are referencing certificate resources and get the
   * {@link java.security.cert.X509Certificate X509Certificate} injected.
   *
   * @return a {@link PropertyToX509CertificateConverter} bean
   */
  @ConditionalOnMissingBean
  @Bean
  @ConfigurationPropertiesBinding
  PropertyToX509CertificateConverter propertyToX509CertificateConverter() {
    return new PropertyToX509CertificateConverter();
  }

  /**
   * Creates the bean the allows us to use property values that are referencing private key resources and get the
   * {@link java.security.PrivateKey PrivateKey} injected.
   *
   * @return a {@link PropertyToPrivateKeyConverter} bean
   */
  @ConditionalOnMissingBean
  @Bean
  @ConfigurationPropertiesBinding
  PropertyToPrivateKeyConverter propertyToPrivateKeyConverter() {
    return new PropertyToPrivateKeyConverter();
  }

  /**
   * Creates the bean the allows us to use property values that are referencing public key resources and get the
   * {@link java.security.PublicKey PublicKey} injected.
   *
   * @return a {@link PropertyToPublicKeyConverter} bean
   */
  @ConditionalOnMissingBean
  @Bean
  @ConfigurationPropertiesBinding
  PropertyToPublicKeyConverter propertyToPublicKeyConverter() {
    return new PropertyToPublicKeyConverter();
  }

  /**
   * Creates the bean that allows us to a property value that is referencing a registered credential and get a
   * {@link java.util.function.Supplier} to a {@link se.swedenconnect.security.credential.PkiCredential PkiCredential}
   * injected.
   *
   * @return a {@link PkiCredentialReferenceConverter} bean
   */
  @ConditionalOnMissingBean
  @Bean
  @ConfigurationPropertiesBinding
  PkiCredentialReferenceConverter pkiCredentialReferenceConverter() {
    return new PkiCredentialReferenceConverter();
  }

  /**
   * Creates the bean that allows us to a property value that is referencing a registered key store and get a
   * {@link java.util.function.Supplier} to a {@link java.security.KeyStore KeyStore} injected.
   *
   * @return a {@link KeyStoreReferenceConverter} bean
   */
  @ConditionalOnMissingBean
  @Bean
  @ConfigurationPropertiesBinding
  KeyStoreReferenceConverter keyStoreReferenceConverter() {
    return new KeyStoreReferenceConverter();
  }

}
