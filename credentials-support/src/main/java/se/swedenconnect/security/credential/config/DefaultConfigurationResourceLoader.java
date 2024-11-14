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
import org.cryptacular.io.ClassPathResource;
import org.cryptacular.io.FileResource;
import org.cryptacular.io.Resource;
import org.cryptacular.io.URLResource;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Objects;

/**
 * An implementation of {@link ConfigurationResourceLoader} that supports {@code file:}, {@code http:}, {@code https:}
 * and {@code classpath:} prefixes.
 *
 * @author Martin Lindström
 */
public class DefaultConfigurationResourceLoader implements ConfigurationResourceLoader {

  /** Prefix for classpath resources. */
  public static final String CLASSPATH_PREFIX = "classpath:";

  /** Prefix for HTTP URL resources. */
  public static final String HTTP_PREFIX = "http:";

  /** Prefix for HTTPS URL resources. */
  public static final String HTTPS_PREFIX = "https:";

  /** Prefix for file resources. */
  public static final String FILE_PREFIX = "file:";

  /**
   * {@inheritDoc} Supports {@code file:}, {@code http:}, {@code https:} and {@code classpath:} prefixes. For
   * {@code location} strings that does not begin with a prefix, the following rules apply:
   * <ul>
   * <li>If the string starts with a "/", it is assumed to be a file resource with a full path.</li>
   * <li>If the string starts with a ".", it is assumed to be a file resource with a relative path.</li>
   * <li>If the string does not start with a "/", it is assumed that it is a classpath resource. </li>
   * </ul>
   */
  @Nonnull
  @Override
  public InputStream getStream(@Nonnull final String location) throws IOException {
    Objects.requireNonNull(location, "location must not be null");

    final Resource resource;
    if (location.startsWith(CLASSPATH_PREFIX)) {
      resource = new ClassPathResource(location.substring(CLASSPATH_PREFIX.length()));
    }
    else if (location.startsWith(HTTP_PREFIX) || location.startsWith(HTTPS_PREFIX)) {
      resource = new URLResource(new URL(location));
    }
    else if (location.startsWith(FILE_PREFIX)) {
      resource = new FileResource(new File(location.substring(FILE_PREFIX.length())));
    }
    else if (location.startsWith("/") || location.startsWith(".")) {
      resource = new FileResource(new File(location));
    }
    else {
      resource = new ClassPathResource(location);
    }

    return resource.getInputStream();
  }
}
