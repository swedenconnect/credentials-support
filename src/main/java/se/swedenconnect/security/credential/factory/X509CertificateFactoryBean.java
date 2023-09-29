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
package se.swedenconnect.security.credential.factory;

import java.security.cert.X509Certificate;

import org.springframework.beans.factory.config.AbstractFactoryBean;
import org.springframework.core.io.Resource;
import org.springframework.util.Assert;

import se.swedenconnect.security.credential.utils.X509Utils;

/**
 * A factory bean for creating X.509 certificates read from a resource.
 * <p>
 * For Shibboleth users:
 * <br>
 * Basically this class is the same as {@code net.shibboleth.ext.spring.factory.X509CertificateFactoryBean} residing in the
 * {@code net.shibboleth.ext:spring-extensions}.
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 */
public class X509CertificateFactoryBean extends AbstractFactoryBean<X509Certificate> {

  /** The resource holding the certificate. */
  private Resource resource;

  /**
   * Default constructor.
   */
  public X509CertificateFactoryBean() {
  }

  /**
   * Constructor taking a resource/path to a DER- or PEM-encoded certificate.
   *
   * @param resource
   *          the location of the certificate
   */
  public X509CertificateFactoryBean(final Resource resource) {
    this.resource = resource;
  }

  /** {@inheritDoc} */
  @Override
  protected X509Certificate createInstance() throws Exception {
    return X509Utils.decodeCertificate(this.resource);
  }

  /** {@inheritDoc} */
  @Override
  public Class<?> getObjectType() {
    return X509Certificate.class;
  }

  /**
   * Assigns the resource holding the certificate.
   *
   * @param resource
   *          the certificate resource
   */
  public void setResource(final Resource resource) {
    this.resource = resource;
  }

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() throws Exception {
    Assert.notNull(this.resource, "Property 'resource' has not been assigned");
    super.afterPropertiesSet();
  }

}
