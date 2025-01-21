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
package se.swedenconnect.security.credential.spring;

import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import se.swedenconnect.security.credential.spring.converters.PropertyToPrivateKeyConverter;
import se.swedenconnect.security.credential.spring.converters.PropertyToPublicKeyConverter;
import se.swedenconnect.security.credential.spring.converters.PropertyToX509CertificateConverter;

/**
 * Configuration class for converter tests.
 *
 * @author Martin Lindström
 */
@Configuration
public class BaseTestConfiguration {

  @Bean
  @ConfigurationPropertiesBinding
  public PropertyToPrivateKeyConverter propertyToPrivateKeyConverter() {
    return new PropertyToPrivateKeyConverter();
  }

  @Bean
  @ConfigurationPropertiesBinding
  public PropertyToPublicKeyConverter propertyToPublicKeyConverter() {
    return new PropertyToPublicKeyConverter();
  }

  @Bean
  @ConfigurationPropertiesBinding
  public PropertyToX509CertificateConverter propertyToX509CertificateConverter() {
    return new PropertyToX509CertificateConverter();
  }

}
