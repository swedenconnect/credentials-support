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
package se.swedenconnect.security.credential;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Properties;

/**
 * Test cases for LibraryVersion.
 *
 * @author Martin Lindström
 */
public class LibraryVersionTest {

  private String version;

  public LibraryVersionTest() throws Exception {
    final Properties properties = new Properties();
    properties.load(this.getClass().getClassLoader().getResourceAsStream("version.properties"));

    this.version = properties.getProperty("library.version");
    if (this.version.endsWith("-SNAPSHOT")) {
      this.version = this.version.substring(0, this.version.length() - 9);
    }
  }

  @Test
  void testUid() {
    final String[] parts = this.version.split("\\.");
    final String majorAndMinor = parts[0] + "." + parts[1];
    Assertions.assertEquals(majorAndMinor.hashCode(), LibraryVersion.SERIAL_VERSION_UID);
  }

  @Test
  void testVersion() throws Exception {
    Assertions.assertEquals(this.version, LibraryVersion.getVersion(),
        "Expected LibraryVersion.getVersion() to return " + this.version);
  }

}
