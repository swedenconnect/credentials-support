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
package se.swedenconnect.security.credential.spring.config;

import jakarta.annotation.Nonnull;
import org.springframework.core.io.ResourceLoader;
import se.swedenconnect.security.credential.config.ConfigurationResourceLoader;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

/**
 * A Spring-implementation of the {@link ConfigurationResourceLoader} interface.
 *
 * @author Martin Lindström
 */
public class SpringConfigurationResourceLoader implements ConfigurationResourceLoader {

  /** The underlying Spring implementation. */
  private final ResourceLoader resourceLoader;

  /**
   * Constructor.
   *
   * @param resourceLoader the Spring {@link ResourceLoader}
   */
  public SpringConfigurationResourceLoader(final ResourceLoader resourceLoader) {
    this.resourceLoader = Objects.requireNonNull(resourceLoader, "resourceLoader must not be null");
  }

  /** {@inheritDoc} */
  @Nonnull
  @Override
  public InputStream getStream(@Nonnull final String location) throws IOException {
    try {
      return this.resourceLoader.getResource(location).getInputStream();
    }
    catch (final FileNotFoundException e) {
      // Spring's resource loader thinks that a resource with no prefix is a classpath-prefix, but we
      // think that it is reasonable to assume a location that starts with '/' is a full path, and '.' is
      // a relative path.
      //
      if (location.startsWith("/") || location.startsWith(".")) {
        return this.resourceLoader.getResource("file:" + location).getInputStream();
      }
      else {
        throw e;
      }
    }
  }
}
