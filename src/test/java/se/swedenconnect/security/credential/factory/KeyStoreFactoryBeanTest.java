/*
 * Copyright 2020-2021 Sweden Connect
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

import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;

import se.swedenconnect.security.credential.pkcs11conf.MockSunPkcs11Provider;

/**
 * Test cases for KeyStoreFactoryBean.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class KeyStoreFactoryBeanTest {
  
  private final static char[] PW = "secret".toCharArray();
  
  @Before
  public void init() {
    Security.addProvider(new MockSunPkcs11Provider());

    // We let rsa1.jks simulate our PKCS#11 device
    MockSunPkcs11Provider.MockedPkcs11ResourceHolder.getInstance().setResource(new ClassPathResource("rsa1.jks"));
  }

  @After
  public void after() {
    Security.removeProvider(MockSunPkcs11Provider.PROVIDER_BASE_NAME);

    Provider[] providers = Security.getProviders();
    for (Provider p : providers) {
      if (p.getName().contains(MockSunPkcs11Provider.PROVIDER_BASE_NAME)) {
        Security.removeProvider(p.getName());
      }
    }

    MockSunPkcs11Provider.MockedPkcs11ResourceHolder.getInstance().setResource(null);
    MockSunPkcs11Provider.MockedPkcs11ResourceHolder.getInstance().setMockNoCertificate(false);
  }
  
  @Test
  public void testCreateFromJks() throws Exception {
    KeyStoreFactoryBean factory = new KeyStoreFactoryBean();
    factory.setResource(new ClassPathResource("rsa1.jks"));
    factory.setPassword(PW);
    factory.setType("JKS");
    factory.setProvider("SUN");
    factory.afterPropertiesSet();
    
    // Test getters
    Assert.assertEquals("rsa1.jks", factory.getResource().getFilename());
//    Assert.assertArrayEquals(PW, factory.getPassword());
    Assert.assertEquals("JKS", factory.getType());
    Assert.assertEquals("SUN", factory.getProvider());
    
    KeyStore ks = factory.getObject();
    Assert.assertNotNull(ks);
    Assert.assertEquals(KeyStore.class, factory.getObjectType());
    
    // The same with constructors ...
    factory = new KeyStoreFactoryBean(new ClassPathResource("rsa1.jks"), PW);
    factory.afterPropertiesSet();
    Assert.assertNotNull(factory.getObject());
    
    factory = new KeyStoreFactoryBean(new ClassPathResource("rsa1.jks"), PW, "JKS");
    factory.afterPropertiesSet();
    Assert.assertNotNull(factory.getObject());
  }
  
  @Test(expected = IllegalArgumentException.class)
  public void testMissingParameters() throws Exception {
    KeyStoreFactoryBean factory = new KeyStoreFactoryBean();
    factory.setResource(new ClassPathResource("rsa1.jks"));
    factory.afterPropertiesSet();
  }
  

}
