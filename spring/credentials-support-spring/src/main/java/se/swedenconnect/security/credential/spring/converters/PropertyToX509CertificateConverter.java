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
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.convert.converter.ConverterRegistry;
import se.swedenconnect.security.credential.utils.X509Utils;

import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * A {@link Converter} that gets the property value (e.g., {@code classpath:cert.crt}) and instantiates an
 * {@link X509Certificate} object. The converter also handles "inlined" PEM certificates.
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
 * public PropertyToX509CertificateConverter propertyToX509CertificateConverter() {
 *   return new PropertyToX509CertificateConverter();
 * }
 * </pre>
 *
 * @author Martin Lindström (martin@idsec.se)
 */
public class PropertyToX509CertificateConverter extends AbstractResourcePropertyConverter<X509Certificate> {

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public X509Certificate convert(@Nonnull final InputStream inputStream) throws CertificateException {
    return X509Utils.decodeCertificate(inputStream);
  }

  /** {@inheritDoc} */
  @Override
  protected boolean isInlinedPem(@Nonnull final String property) {
    return X509Utils.isInlinedPem(property);
  }

}
