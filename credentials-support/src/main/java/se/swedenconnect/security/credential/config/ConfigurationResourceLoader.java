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
package se.swedenconnect.security.credential.config;

import jakarta.annotation.Nonnull;

import java.io.IOException;
import java.io.InputStream;

/**
 * An interface for loading configuration values that are "locations". Depending on the framework, loading of resources
 * may differ.
 *
 * @author Martin Lindström
 */
public interface ConfigurationResourceLoader {

  /**
   * Gets an {@link InputStream} for the resource.
   *
   * @param location resource location
   * @return an {@link InputStream}
   * @throws IOException for failures to open the stream
   */
  @Nonnull
  InputStream getStream(@Nonnull final String location) throws IOException;

}
