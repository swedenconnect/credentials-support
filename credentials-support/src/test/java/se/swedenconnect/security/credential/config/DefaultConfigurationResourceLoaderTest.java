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
package se.swedenconnect.security.credential.config;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.stream.Collectors;

/**
 * Test cases for DefaultConfigurationResourceLoader.
 *
 * @author Martin Lindström
 */
public class DefaultConfigurationResourceLoaderTest {

  public static final String CONTENTS = "Hello world!";

  private final DefaultConfigurationResourceLoader loader = new DefaultConfigurationResourceLoader();

  @Test
  void testClasspathPrefix() throws IOException {
    try (final InputStream is = this.loader.getStream("classpath:resource.txt")) {
      Assertions.assertEquals(CONTENTS, getContents(is));
    }
  }

  @Test
  void testClasspathNoPrefix() throws IOException {
    try (final InputStream is = this.loader.getStream("resource.txt")) {
      Assertions.assertEquals(CONTENTS, getContents(is));
    }
  }

  @Test
  void testFilePrefix() throws IOException {
    try (final InputStream is = this.loader.getStream("file:src/test/resources/resource.txt")) {
      Assertions.assertEquals(CONTENTS, getContents(is));
    }

    final String fullpath = System.getProperty("user.dir") + "/src/test/resources/resource.txt";
    try (final InputStream is = this.loader.getStream("file:" + fullpath)) {
      Assertions.assertEquals(CONTENTS, getContents(is));
    }
  }

  @EnabledOnOs({ OS.LINUX, OS.MAC })
  @Test
  void testFileNoPrefix() throws IOException {
    final String fullpath = System.getProperty("user.dir") + "/src/test/resources/resource.txt";
    try (final InputStream is = this.loader.getStream(fullpath)) {
      Assertions.assertEquals(CONTENTS, getContents(is));
    }
    try (final InputStream is = this.loader.getStream("./src/test/resources/resource.txt")) {
      Assertions.assertEquals(CONTENTS, getContents(is));
    }
  }

  private static String getContents(final InputStream inputStream) {
    return new BufferedReader(new InputStreamReader(inputStream)).lines().collect(Collectors.joining("\n"));
  }

}
