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

import java.security.PrivateKey;

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
import se.swedenconnect.security.credential.converters.PropertyToPrivateKeyConverterTest.KeyConfig;

/**
 * Test cases for PropertyToPrivateKeyConverter.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@RunWith(SpringRunner.class)
@EnableConfigurationProperties(value = KeyConfig.class)
@TestPropertySource(locations = { "classpath:application.properties" })
public class PropertyToPrivateKeyConverterTest {
  
  @Autowired
  ApplicationContext context;  
  
  @Autowired(required = false)
  PropertyToPrivateKeyConverter propertyToPrivateKeyConverter;
  
  @Autowired(required = false)
  PrivateKey testKey;
  
  @Test
  public void testConvert() throws Exception {
    PropertyToPrivateKeyConverter converter = new PropertyToPrivateKeyConverter();
    converter.setApplicationContext(this.context);
    
    PrivateKey pk = converter.convert("classpath:rsa1.pkcs8.key");
    Assert.assertNotNull(pk);
  }
  
  @Test(expected = IllegalArgumentException.class)
  public void testConvertFailed() throws Exception {
    PropertyToPrivateKeyConverter converter = new PropertyToPrivateKeyConverter();
    converter.setApplicationContext(this.context);
    
    converter.convert("classpath:not-found.key");
  }
  
  @Test
  public void testConverterBean() throws Exception {
    Assert.assertNotNull("PropertyToPrivateKeyConverter bean is not present", this.propertyToPrivateKeyConverter);
    Assert.assertNotNull(this.propertyToPrivateKeyConverter.convert("classpath:rsa1.pkcs8.key"));
  }
  
  @Test
  public void testSpringContextPrivateKeySet() throws Exception {
    Assert.assertNotNull(this.testKey);
  }

  @Configuration  
  public static class Config {
        
    @Bean
    @ConfigurationPropertiesBinding
    public PropertyToPrivateKeyConverter propertyToPrivateKeyConverter() {
      return new PropertyToPrivateKeyConverter();
    }
  }

  @Configuration
  @ConfigurationProperties
  public static class KeyConfig {
    @Setter
    private PrivateKey testkey;
    
    @Bean
    public PrivateKey testKey() {
      return this.testkey;
    }
  }    

}
