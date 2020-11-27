/*
 * Copyright 2020 Sweden Connect
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

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.convert.converter.ConverterRegistry;
import org.springframework.core.io.Resource;

/**
 * A {@link Converter} that gets the property value (e.g., {@code classpath:cert.crt}) and instantiates a
 * {@link X509Certificate} object.
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
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class PropertyToX509CertificateConverter implements Converter<String, X509Certificate>, ApplicationContextAware {

  /** The application context. */
  private ApplicationContext applicationContext;

  /** Factory for creating certificates. */
  private static CertificateFactory factory = null;

  static {
    try {
      factory = CertificateFactory.getInstance("X.509");
    }
    catch (CertificateException e) {
      throw new SecurityException(e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public X509Certificate convert(final String source) {

    final Resource resource = this.applicationContext.getResource(source);

    try (InputStream is = resource.getInputStream()) {
      return (X509Certificate) factory.generateCertificate(is);
    }
    catch (CertificateException | IOException e) {
      throw new IllegalArgumentException(String.format("Failed to convert %s to a X509Certificate", source));
    }
  }

  /** {@inheritDoc} */
  @Override
  public void setApplicationContext(final ApplicationContext applicationContext) throws BeansException {
    this.applicationContext = applicationContext;
  }

}
