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

import java.security.Provider;
import java.security.Security;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;

import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.pkcs11conf.MockSunPkcs11Provider;

/**
 * Test cases for PkiCredentialFactoryBean.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class PkiCredentialFactoryBeanTest {

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
  public void testObjectType() throws Exception {
    final PkiCredentialFactoryBean factory = new PkiCredentialFactoryBean();
    Assert.assertEquals(PkiCredential.class, factory.getObjectType());
  }
  
  @Test(expected = IllegalArgumentException.class)
  public void testMissingConfiguration1() throws Exception {
    final PkiCredentialFactoryBean factory = new PkiCredentialFactoryBean();
    factory.setCertificate(new ClassPathResource("rsa1.crt"));
    factory.afterPropertiesSet();
  }
  
  @Test(expected = SecurityException.class)
  public void testMissingConfiguration2() throws Exception {
    final PkiCredentialFactoryBean factory = new PkiCredentialFactoryBean();
    factory.setCertificate(new ClassPathResource("rsa1.crt"));
    factory.setSingleton(false);
    factory.getObject();
  }  
  
  @Test
  public void testBasicCredential() throws Exception {
    final PkiCredentialFactoryBean factory = new PkiCredentialFactoryBean();
    factory.setCertificate(new ClassPathResource("rsa1.crt"));
    factory.setPrivateKey(new ClassPathResource("rsa1.pkcs8.key"));
    factory.setName("test");
    factory.afterPropertiesSet();
    final PkiCredential credential = factory.getObject();
    Assert.assertTrue(credential instanceof BasicCredential);
    Assert.assertEquals("test", credential.getName());
    factory.destroy();
  }
  
  @Test
  public void testKeyStoreCredential() throws Exception {
    PkiCredentialFactoryBean factory = new PkiCredentialFactoryBean();
    factory.setResource(new ClassPathResource("rsa1.jks"));
    factory.setPassword(PW);
    factory.setAlias("test");
    factory.afterPropertiesSet();
    PkiCredential credential = factory.getObject();
    Assert.assertTrue(credential instanceof KeyStoreCredential);
    factory.destroy();
    
    factory = new PkiCredentialFactoryBean();
    factory.setResource(new ClassPathResource("rsa1.jks"));
    factory.setPassword(PW);
    factory.setAlias("test");
    factory.setKeyPassword(PW);
    factory.setType("JKS");
    factory.setProvider("SUN");
    factory.afterPropertiesSet();
    credential = factory.getObject();
    Assert.assertTrue(credential instanceof KeyStoreCredential);
    factory.destroy();
  }
  
}
