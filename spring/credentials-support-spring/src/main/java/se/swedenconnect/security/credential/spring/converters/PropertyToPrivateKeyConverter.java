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
package se.swedenconnect.security.credential.spring.converters;

import jakarta.annotation.Nonnull;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.convert.converter.ConverterRegistry;
import se.swedenconnect.security.credential.utils.KeyUtils;

import java.io.InputStream;
import java.security.KeyException;
import java.security.PrivateKey;

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
public class PropertyToPrivateKeyConverter extends AbstractResourcePropertyConverter<PrivateKey> {

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public PrivateKey convert(@Nonnull final InputStream inputStream) throws KeyException {
    return KeyUtils.decodePrivateKey(inputStream);
  }

  /** {@inheritDoc} */
  @Override
  protected boolean isInlinedPem(@Nonnull final String property) {
    return KeyUtils.isInlinedPem(property);
  }

}
