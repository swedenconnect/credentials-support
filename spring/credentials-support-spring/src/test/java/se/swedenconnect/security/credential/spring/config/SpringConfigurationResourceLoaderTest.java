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
package se.swedenconnect.security.credential.spring.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ResourceLoader;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test cases for SpringConfigurationResourceLoader.
 *
 * @author Martin Lindström
 */
@ExtendWith(SpringExtension.class)
class SpringConfigurationResourceLoaderTest {

  public static final String CONTENTS = "Hello world!";

  @Autowired
  ResourceLoader resourceLoader;

  @Test
  void testClasspathPrefix() throws IOException {
    final SpringConfigurationResourceLoader loader = new SpringConfigurationResourceLoader(this.resourceLoader);
    try (final InputStream is = loader.getStream("classpath:resource.txt")) {
      assertEquals(CONTENTS, getContents(is));
    }
  }

  @Test
  void testClasspathNoPrefix() throws IOException {
    final SpringConfigurationResourceLoader loader = new SpringConfigurationResourceLoader(this.resourceLoader);
    try (final InputStream is = loader.getStream("resource.txt")) {
      assertEquals(CONTENTS, getContents(is));
    }
  }

  @Test
  void testFilePrefix() throws IOException {
    final SpringConfigurationResourceLoader loader = new SpringConfigurationResourceLoader(this.resourceLoader);
    try (final InputStream is = loader.getStream("file:src/test/resources/resource.txt")) {
      assertEquals(CONTENTS, getContents(is));
    }

    final String fullpath = System.getProperty("user.dir") + "/src/test/resources/resource.txt";
    try (final InputStream is = loader.getStream("file:" + fullpath)) {
      assertEquals(CONTENTS, getContents(is));
    }
  }

  @EnabledOnOs({ OS.LINUX, OS.MAC })
  @Test
  void testFileNoPrefix() throws IOException {
    final SpringConfigurationResourceLoader loader = new SpringConfigurationResourceLoader(this.resourceLoader);
    final String fullpath = System.getProperty("user.dir") + "/src/test/resources/resource.txt";
    try (final InputStream is = loader.getStream(fullpath)) {
      assertEquals(CONTENTS, getContents(is));
    }
    try (final InputStream is = loader.getStream("./src/test/resources/resource.txt")) {
      assertEquals(CONTENTS, getContents(is));
    }
  }

  @Test
  void testNotFound() {
    final SpringConfigurationResourceLoader loader = new SpringConfigurationResourceLoader(this.resourceLoader);
    assertThrows(IOException.class, () -> loader.getStream("not-found.txt"));
  }

  private static String getContents(final InputStream inputStream) {
    return new BufferedReader(new InputStreamReader(inputStream)).lines().collect(Collectors.joining("\n"));
  }

}
