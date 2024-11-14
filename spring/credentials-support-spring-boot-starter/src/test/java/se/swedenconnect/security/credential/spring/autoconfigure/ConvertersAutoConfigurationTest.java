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

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import se.swedenconnect.security.credential.spring.converters.PropertyToPrivateKeyConverter;
import se.swedenconnect.security.credential.spring.converters.PropertyToX509CertificateConverter;

/**
 * Test cases for {@link ConvertersAutoConfiguration}.
 *
 * @author Martin Lindström
 */
class ConvertersAutoConfigurationTest {

  private final ApplicationContextRunner contextRunner = new ApplicationContextRunner();

  @Test
  void testCreateBeanSetup() {
    this.contextRunner
        .withConfiguration(AutoConfigurations.of(ConvertersAutoConfiguration.class))
        .run(context -> {
          Assertions.assertThat(context).hasSingleBean(PropertyToX509CertificateConverter.class);
          Assertions.assertThat(context).hasSingleBean(PropertyToPrivateKeyConverter.class);
        });
  }

}
