/*
 * Copyright 2020-2022 Sweden Connect
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

import org.junit.Assert;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;

/**
 * Test cases for X509CertificateFactoryBean.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class X509CertificateFactoryBeanTest {

  @Test
  public void testFactory() throws Exception {
    X509CertificateFactoryBean factory = new X509CertificateFactoryBean();
    factory.setResource(new ClassPathResource("rsa1.crt"));
    factory.afterPropertiesSet();
    
    Assert.assertNotNull(factory.getObject());
    Assert.assertEquals(X509Certificate.class, factory.getObjectType());
    
    factory = new X509CertificateFactoryBean(new ClassPathResource("rsa1.crt"));
    factory.afterPropertiesSet();
    
    Assert.assertNotNull(factory.getObject());
  }
  
  @Test(expected = IllegalArgumentException.class)
  public void testMissingResource() throws Exception {
    X509CertificateFactoryBean factory = new X509CertificateFactoryBean();
    factory.afterPropertiesSet();
  }

}
