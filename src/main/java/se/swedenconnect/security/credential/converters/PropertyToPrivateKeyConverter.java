/*
 * Copyright 2020-2023 Sweden Connect
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
package se.swedenconnect.security.credential.converters;

import java.security.KeyException;
import java.security.PrivateKey;

import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.convert.converter.ConverterRegistry;

import se.swedenconnect.security.credential.utils.PrivateKeyUtils;

/**
 * A {@link Converter} that gets the property value (e.g., {@code classpath:signing.key}) and instantiates a
 * {@link PrivateKey} object.
 * <p>
 * Note: The converter only handles non-encrypted private keys in DER, PEM, and PKCS#8 formats.
 * </p>
 * <p>
 * To use this converter it has to be instantiated as a bean and then registered in the registry using
 * {@link ConverterRegistry#addConverter(Converter)}.
 * </p>
 * <p>
 * If you are using Spring Boot, do:
 * </p>
 *
 * <pre>
 * &#64;Bean
 * &#64;ConfigurationPropertiesBinding
 * public PropertyToPrivateKeyConverter propertyToPrivateKeyConverter() {
 *   return new PropertyToPrivateKeyConverter();
 * }
 * </pre>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class PropertyToPrivateKeyConverter implements Converter<String, PrivateKey>, ApplicationContextAware {

  /** The application context. */
  private ApplicationContext applicationContext;

  /** {@inheritDoc} */
  @Override
  public PrivateKey convert(final String source) {

    try {
      return PrivateKeyUtils.decodePrivateKey(this.applicationContext.getResource(source));
    }
    catch (final KeyException e) {
      throw new IllegalArgumentException("Failed to instantiate private key object from " + source, e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public void setApplicationContext(final ApplicationContext applicationContext) throws BeansException {
    this.applicationContext = applicationContext;
  }

}
