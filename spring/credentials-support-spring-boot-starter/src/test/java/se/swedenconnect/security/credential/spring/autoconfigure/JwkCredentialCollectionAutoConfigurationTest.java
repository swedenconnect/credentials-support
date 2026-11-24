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
package se.swedenconnect.security.credential.spring.autoconfigure;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import se.swedenconnect.security.credential.PkiCredentialCollection;
import se.swedenconnect.security.credential.nimbus.JwkCredentialCollection;

import java.util.List;

/**
 * Test cases for {@link JwkCredentialCollectionAutoConfiguration}.
 *
 * @author Martin Lindström
 */
class JwkCredentialCollectionAutoConfigurationTest {

  private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
      .withConfiguration(AutoConfigurations.of(JwkCredentialCollectionAutoConfiguration.class));

  @Test
  void testCreated() {
    final PkiCredentialCollection collection = new PkiCredentialCollection(List.of());
    this.contextRunner
        .withBean("credential-collection", PkiCredentialCollection.class, () -> collection)
        .run(context -> {
          Assertions.assertThat(context).hasSingleBean(JwkCredentialCollection.class);
          Assertions.assertThat(context.getBean(JwkCredentialCollection.class).getCollection()).isSameAs(collection);
        });
  }

  @Test
  void testNoCollection() {
    this.contextRunner
        .run(context -> Assertions.assertThat(context).doesNotHaveBean(JwkCredentialCollection.class));
  }

  @Test
  void testNimbusNotOnClasspath() {
    this.contextRunner
        .withClassLoader(new FilteredClassLoader(JwkCredentialCollection.class))
        .withBean("credential-collection", PkiCredentialCollection.class, () -> new PkiCredentialCollection(List.of()))
        .run(context -> Assertions.assertThat(context).doesNotHaveBean(JwkCredentialCollection.class));
  }

  @Test
  void testUserDefinedBean() {
    final PkiCredentialCollection collection = new PkiCredentialCollection(List.of());
    final JwkCredentialCollection custom = new JwkCredentialCollection(collection);
    this.contextRunner
        .withBean("credential-collection", PkiCredentialCollection.class, () -> collection)
        .withBean("custom", JwkCredentialCollection.class, () -> custom)
        .run(context -> Assertions.assertThat(context.getBean(JwkCredentialCollection.class)).isSameAs(custom));
  }

}
