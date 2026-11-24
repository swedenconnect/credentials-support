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

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import se.swedenconnect.security.credential.PkiCredentialCollection;
import se.swedenconnect.security.credential.nimbus.JwkCredentialCollection;

/**
 * Autoconfiguration that creates a {@link JwkCredentialCollection} bean wrapping the {@code credential-collection}
 * bean. Only active if the {@code credentials-support-nimbus} module is on the classpath.
 *
 * @author Martin Lindström
 */
@AutoConfiguration(after = SpringCredentialBundlesAutoConfiguration.class)
@ConditionalOnClass(JwkCredentialCollection.class)
public class JwkCredentialCollectionAutoConfiguration {

  /**
   * Creates a {@link JwkCredentialCollection} bean named {@code jwk-credential-collection}.
   *
   * @param collection the credential collection
   * @return a {@link JwkCredentialCollection} bean
   */
  @ConditionalOnMissingBean
  @ConditionalOnBean(name = "credential-collection")
  @Bean("jwk-credential-collection")
  JwkCredentialCollection jwkCredentialCollection(
      @Qualifier("credential-collection") final PkiCredentialCollection collection) {
    return new JwkCredentialCollection(collection);
  }

}
