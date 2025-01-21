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
package se.swedenconnect.security.credential.spring;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.support.DefaultPropertySourceFactory;
import org.springframework.core.io.support.EncodedResource;

import java.io.IOException;

/**
 * Supports tests.
 *
 * @author Martin Lindström
 */
public class YamlPropertyLoaderFactory extends DefaultPropertySourceFactory {

  private final YamlPropertySourceLoader yamlPropertySourceLoader = new YamlPropertySourceLoader();

  @Override
  @Nonnull
  public PropertySource<?> createPropertySource(@Nullable final String name, @Nonnull final EncodedResource resource)
      throws IOException {
    final String parsedName;
    if (name != null && !name.isEmpty()) {
      parsedName = name;
    }
    else {
      parsedName = resource.getResource().getFilename();
    }
    return this.yamlPropertySourceLoader.load(parsedName, resource.getResource()).get(0);
  }
}
