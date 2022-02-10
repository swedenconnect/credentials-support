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
package se.swedenconnect.security.credential.converters;

import java.security.cert.X509Certificate;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import lombok.Setter;
import se.swedenconnect.security.credential.converters.PropertyToX509CertificateConverterTest.CertConfig;

/**
 * Test cases for PropertyToX509CertificateConverter.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@RunWith(SpringRunner.class)
@EnableConfigurationProperties(value = CertConfig.class)
@TestPropertySource(locations = { "classpath:application.properties" })
public class PropertyToX509CertificateConverterTest {

  @Autowired
  ApplicationContext context;  
  
  @Autowired(required = false)
  PropertyToX509CertificateConverter propertyToX509CertificateConverter;
  
  @Autowired(required = false)
  X509Certificate testCert;
  
  @Test
  public void testConvert() throws Exception {
    PropertyToX509CertificateConverter converter = new PropertyToX509CertificateConverter();
    converter.setApplicationContext(this.context);
    
    X509Certificate cert = converter.convert("classpath:rsa1.crt");
    Assert.assertNotNull(cert);
  }
  
  @Test(expected = IllegalArgumentException.class)
  public void testConvertFailed() throws Exception {
    PropertyToX509CertificateConverter converter = new PropertyToX509CertificateConverter();
    converter.setApplicationContext(this.context);
    
    converter.convert("classpath:not-found.crt");
  }
  
  @Test
  public void testConverterBean() throws Exception {
    Assert.assertNotNull("PropertyToX509CertificateConverter bean is not present", this.propertyToX509CertificateConverter);
    Assert.assertNotNull(this.propertyToX509CertificateConverter.convert("classpath:rsa1.crt"));
  }
  
  @Test
  public void testSpringContextCertSet() throws Exception {
    Assert.assertNotNull(this.testCert);
  }

  @Configuration  
  public static class Config {
        
    @Bean
    @ConfigurationPropertiesBinding
    public PropertyToX509CertificateConverter propertyToX509CertificateConverter() {
      return new PropertyToX509CertificateConverter();
    }
  }

  @Configuration
  @ConfigurationProperties
  public static class CertConfig {
    @Setter
    private X509Certificate testcert;
    
    @Bean
    public X509Certificate testCert() {
      return this.testcert;
    }
  }    


}
