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
package se.swedenconnect.security.credential.spring.converters;

import jakarta.annotation.Nonnull;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.InputStreamResource;
import org.springframework.core.io.Resource;
import org.springframework.util.ResourceUtils;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;

/**
 * Abstract base class for converters that convert a resource property value into an object.
 *
 * @author Martin Lindström
 */
public abstract class AbstractResourcePropertyConverter<T> implements Converter<String, T>, ApplicationContextAware {

  /** The application context. */
  private ApplicationContext applicationContext;

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public T convert(@Nonnull final String source) {
    try {
      final Resource resource = this.isInlinedPem(source)
          ? new InputStreamResource(new ByteArrayInputStream(source.getBytes()))
          : this.applicationContext.getResource(getResourceUrl(source));
      try (final InputStream inputStream = resource.getInputStream()) {
        return this.convert(inputStream);
      }
    }
    catch (final Exception e) {
      throw new IllegalArgumentException("Failed to instantiate object from " + source, e);
    }
  }

  private static String getResourceUrl(final String location) {
    if (ResourceUtils.isUrl(location)) {
      return location;
    }
    final File file = new File(location);
    return file.isAbsolute() ? ResourceUtils.FILE_URL_PREFIX + location : location;
  }

  /**
   * Converts the input stream to the object supported by the converter.
   * <p>
   * The stream must not be closed.
   * </p>
   *
   * @param inputStream the stream
   * @return the object
   * @throws Exception for conversion errors
   */
  @Nonnull
  protected abstract T convert(@Nonnull final InputStream inputStream) throws Exception;

  /**
   * Tells whether the property value holds an "inlined" PEM representation of the object.
   *
   * @param property the property value
   * @return {@code true} if the property holds a PEM object, and {@code false} otherwise
   */
  protected abstract boolean isInlinedPem(@Nonnull final String property);

  /** {@inheritDoc} */
  @Override
  public void setApplicationContext(@Nonnull final ApplicationContext applicationContext) throws BeansException {
    this.applicationContext = applicationContext;
  }

}
