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
package se.swedenconnect.security.credential.spring;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * For testing.
 *
 * @author Martin Lindström
 */
@Configuration
@EnableConfigurationProperties(TestConfigurationProperties.class)
public class TestConfiguration {

  private final TestConfigurationProperties properties;

  public TestConfiguration(final TestConfigurationProperties properties) {
    this.properties = properties;
  }

  @Bean("testobject1")
  TestObject testObject1() {
    return new TestObject(this.properties.getObject1());
  }

}
