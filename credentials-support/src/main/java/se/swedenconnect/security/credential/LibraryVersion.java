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
package se.swedenconnect.security.credential;

/**
 * Internal class used for serialization across library classes.
 *
 * @author Martin Lindström
 */
public final class LibraryVersion {

  private static final int MAJOR = 2;
  private static final int MINOR = 0;
  private static final int PATCH = 0;

  /**
   * Global serialization value for classes.
   */
  public static final long SERIAL_VERSION_UID = (MAJOR + "." + MINOR).hashCode();

  /**
   * Gets the version string.
   *
   * @return the version string
   */
  public static String getVersion() {
    return MAJOR + "." + MINOR + "." + PATCH;
  }

  private LibraryVersion() {}
}