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
package se.swedenconnect.security.credential.spring.autoconfigure;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import se.swedenconnect.security.credential.bundle.CredentialBundleRegistry;
import se.swedenconnect.security.credential.bundle.CredentialBundles;
import se.swedenconnect.security.credential.config.ConfigurationResourceLoader;
import se.swedenconnect.security.credential.factory.PkiCredentialFactory;
import se.swedenconnect.security.credential.monitoring.CredentialMonitorBean;
import se.swedenconnect.security.credential.spring.actuator.CredentialMonitorHealthIndicator;

/**
 * Test cases for {@link SpringCredentialBundlesAutoConfiguration}.
 *
 * @author Martin Lindström
 */
class SpringCredentialBundlesAutoConfigurationTest {

  private final ApplicationContextRunner contextRunner = new ApplicationContextRunner();

  @Test
  void testCreateBeanSetup() {
    this.contextRunner
        .withConfiguration(AutoConfigurations.of(
            SpringCredentialBundlesAutoConfiguration.class, ConvertersAutoConfiguration.class))
        .withPropertyValues(
            "credential.bundles.key-store.keystore1.location=classpath:test-1.jks",
            "credential.bundles.key-store.keystore1.password=secret",
            "credential.bundles.jks.test1.store-reference=keystore1",
            "credential.bundles.jks.test1.name=Test1",
            "credential.bundles.jks.test1.key.alias=test1",
            "credential.bundles.jks.test1.key.key-password=secret",
            "credential.bundles.jks.test1.monitor=true",
            "credential.bundles.monitoring.enabled=true")
        .run(context -> {
          Assertions.assertThat(context).hasSingleBean(CredentialBundles.class);
          final CredentialBundles credentialBundles = context.getBean(CredentialBundles.class);
          Assertions.assertThat(credentialBundles.getCredential("test1")).isNotNull();
          Assertions.assertThat(credentialBundles.getKeyStore("keystore1")).isNotNull();

          Assertions.assertThat(context).hasSingleBean(CredentialBundleRegistry.class);
          Assertions.assertThat(context).hasSingleBean(ConfigurationResourceLoader.class);
          Assertions.assertThat(context).hasSingleBean(PkiCredentialFactory.class);
          Assertions.assertThat(context).hasSingleBean(CredentialMonitorBean.class);
        });
  }

  @Test
  void testCreateHealthEndpointExistingCredentialMonitorBean() {

    final CredentialMonitorBean monitorBean = Mockito.mock(CredentialMonitorBean.class);
    Mockito.doNothing().when(monitorBean).test();

    this.contextRunner
        .withConfiguration(AutoConfigurations.of(
            SpringCredentialBundlesAutoConfiguration.class, ConvertersAutoConfiguration.class))
        .withBean(CredentialMonitorBean.class, () -> monitorBean)
        .withPropertyValues(
            "credential.bundles.key-store.keystore1.location=classpath:test-1.jks",
            "credential.bundles.key-store.keystore1.password=secret",
            "credential.bundles.jks.test1.store-reference=keystore1",
            "credential.bundles.jks.test1.name=Test1",
            "credential.bundles.jks.test1.key.alias=test1",
            "credential.bundles.jks.test1.key.key-password=secret",
            "credential.bundles.jks.test1.monitor=true",
            "credential.monitoring.enabled=true",
            "credential.monitoring.health-endpoint-enabled=true")
        .run(context -> Assertions.assertThat(context).hasSingleBean(CredentialMonitorHealthIndicator.class));
  }
}
