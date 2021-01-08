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
package se.swedenconnect.security.credential.pkcs11conf;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;

import se.swedenconnect.security.credential.PkiCredential;

/**
 * Test cases for DefaultPkcs11FileConfiguration.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultPkcs11ConfigurationTest {

  private final static char[] PIN = "secret".toCharArray();
  private final static String ALIAS = "test";

  private static final String LIBRARY = "/opt/foo/lib/libpkcs11.so";
  private static final String NAME = "mocked";

  @Before
  public void init() {
    Security.insertProviderAt(new MockSunPkcs11Provider(), 1);

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
  public void testUsage() throws Exception {
    final DefaultPkcs11Configuration conf = new DefaultPkcs11Configuration(getAbsolutePath("cfg1.txt"));
    conf.setBaseProviderName(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
    conf.afterPropertiesSet();

    Provider provider = conf.getProvider();
    Assert.assertEquals(MockSunPkcs11Provider.PROVIDER_BASE_NAME + "-Foo", provider.getName());

    PkiCredential cred = conf.getCredentialProvider().get(provider, ALIAS, PIN);
    Assert.assertNotNull(cred);
    Assert.assertNotNull(cred.getCertificate());
    Assert.assertNotNull(cred.getPrivateKey());
    
    // Get private key should also work
    Assert.assertNotNull(conf.getPrivateKeyProvider().get(provider, ALIAS, PIN));    
  }

  @Test
  public void testIndividualSettings() throws Exception {
    final DefaultPkcs11Configuration conf = new DefaultPkcs11Configuration(LIBRARY, NAME, "Slot1", 1);
    conf.setBaseProviderName(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
    conf.afterPropertiesSet();

    Provider provider = conf.getProvider();
    Assert.assertEquals(MockSunPkcs11Provider.PROVIDER_BASE_NAME + "-" + NAME, provider.getName());

    PkiCredential cred = conf.getCredentialProvider().get(provider, ALIAS, PIN);
    Assert.assertNotNull(cred);
    Assert.assertNotNull(cred.getCertificate());
    Assert.assertNotNull(cred.getPrivateKey());
  }

  @Test
  public void testStaticicallyConfiguredProvider() throws Exception {
    Security.removeProvider(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
    Security.insertProviderAt(MockSunPkcs11Provider.createStaticallyConfigured(), 1);

    final DefaultPkcs11Configuration conf = new DefaultPkcs11Configuration();
    conf.setBaseProviderName(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
    conf.afterPropertiesSet();

    Provider provider = conf.getProvider();
    Assert.assertEquals(MockSunPkcs11Provider.PROVIDER_BASE_NAME, provider.getName());

    PkiCredential cred = conf.getCredentialProvider().get(provider, ALIAS, PIN);
    Assert.assertNotNull(cred);
    Assert.assertNotNull(cred.getCertificate());
    Assert.assertNotNull(cred.getPrivateKey());
  }

  @Test
  public void testStaticicallyConfiguredProviderNoInit() throws Exception {
    Security.removeProvider(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
    Security.insertProviderAt(MockSunPkcs11Provider.createStaticallyConfigured(), 1);

    final DefaultPkcs11Configuration conf = new DefaultPkcs11Configuration();
    conf.setBaseProviderName(MockSunPkcs11Provider.PROVIDER_BASE_NAME);

    Provider provider = conf.getProvider();
    Assert.assertEquals(MockSunPkcs11Provider.PROVIDER_BASE_NAME, provider.getName());

    PkiCredential cred = conf.getCredentialProvider().get(provider, ALIAS, PIN);
    Assert.assertNotNull(cred);
    Assert.assertNotNull(cred.getCertificate());
    Assert.assertNotNull(cred.getPrivateKey());
  }
  
  @Test(expected = Pkcs11ConfigurationException.class)
  public void testMissingParamsNoInit() throws Exception {
    final DefaultPkcs11Configuration conf = new DefaultPkcs11Configuration();
    conf.setBaseProviderName(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
    conf.getProvider();
  }

  @Test
  public void testStaticicallyConfiguredProviderIllegalParams() throws Exception {
    Security.removeProvider(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
    Security.insertProviderAt(MockSunPkcs11Provider.createStaticallyConfigured(), 1);
    DefaultPkcs11Configuration conf = null;
    
    try {
      conf = new DefaultPkcs11Configuration();
      conf.setConfigurationFile(getAbsolutePath("cfg1.txt"));
      conf.setBaseProviderName(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
      conf.afterPropertiesSet();
      Assert.fail("Expeced Pkcs11ConfigurationException");
    }
    catch (Pkcs11ConfigurationException e) {
    }
    
    try {
      conf = new DefaultPkcs11Configuration();
      conf.setLibrary(LIBRARY);
      conf.setBaseProviderName(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
      conf.afterPropertiesSet();
      Assert.fail("Expeced Pkcs11ConfigurationException");
    }
    catch (Pkcs11ConfigurationException e) {
    }
    
    try {
      conf = new DefaultPkcs11Configuration();
      conf.setName(NAME);
      conf.setBaseProviderName(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
      conf.afterPropertiesSet();
      Assert.fail("Expeced Pkcs11ConfigurationException");
    }
    catch (Pkcs11ConfigurationException e) {
    }
    
    try {
      conf = new DefaultPkcs11Configuration();
      conf.setSlot("1");
      conf.setBaseProviderName(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
      conf.afterPropertiesSet();
      Assert.fail("Expeced Pkcs11ConfigurationException");
    }
    catch (Pkcs11ConfigurationException e) {
    }
    
    try {
      conf = new DefaultPkcs11Configuration();
      conf.setSlotListIndex(1);
      conf.setBaseProviderName(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
      conf.afterPropertiesSet();
      Assert.fail("Expeced Pkcs11ConfigurationException");
    }
    catch (Pkcs11ConfigurationException e) {
    }
  }

  @Test(expected = Pkcs11ConfigurationException.class)
  public void testProviderNotFound() throws Exception {
    Security.removeProvider(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
    final DefaultPkcs11Configuration conf = new DefaultPkcs11Configuration();
    conf.setBaseProviderName(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
    conf.afterPropertiesSet();
  }
  
  @Test(expected = Pkcs11ConfigurationException.class)
  public void testProviderNotFound2() throws Exception {    
    final DefaultPkcs11Configuration conf = new DefaultPkcs11Configuration();
    conf.setBaseProviderName(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
    Security.removeProvider(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
    conf.getProvider();
  }
  
  @Test(expected = Pkcs11ConfigurationException.class)
  public void testInvalidConfiguration() throws Exception {
    final DefaultPkcs11Configuration conf = new DefaultPkcs11Configuration(getAbsolutePath("cfg-nolib.txt"));
    conf.setBaseProviderName(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
    conf.afterPropertiesSet();

    conf.getProvider();
  }
  
  @Test
  public void testDoubleCalls() throws Exception {
    final DefaultPkcs11Configuration conf = new DefaultPkcs11Configuration(getAbsolutePath("cfg1.txt"));
    conf.setBaseProviderName(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
    conf.afterPropertiesSet();

    Provider provider = conf.getProvider();
    Assert.assertEquals(MockSunPkcs11Provider.PROVIDER_BASE_NAME + "-Foo", provider.getName());

    PkiCredential cred = conf.getCredentialProvider().get(provider, ALIAS, PIN);
    Assert.assertNotNull(cred);
    Assert.assertNotNull(cred.getCertificate());
    Assert.assertNotNull(cred.getPrivateKey());
    
    final DefaultPkcs11Configuration conf2 = new DefaultPkcs11Configuration(LIBRARY, "Foo", null, null);
    conf2.setBaseProviderName(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
    conf2.afterPropertiesSet();

    provider = conf2.getProvider();
    Assert.assertEquals(MockSunPkcs11Provider.PROVIDER_BASE_NAME + "-Foo", provider.getName());

    cred = conf2.getCredentialProvider().get(provider, ALIAS, PIN);
    Assert.assertNotNull(cred);
    Assert.assertNotNull(cred.getCertificate());
    Assert.assertNotNull(cred.getPrivateKey());
  }
  
  @Test
  public void testMissingPrivateKey() throws Exception {    
    final DefaultPkcs11Configuration conf = new DefaultPkcs11Configuration(getAbsolutePath("cfg1.txt"));
    conf.setBaseProviderName(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
    conf.afterPropertiesSet();

    PrivateKey pk = conf.getPrivateKeyProvider().get(conf.getProvider(), "not-found", PIN);
    Assert.assertNull(pk);
  }
  
  @Test(expected = SecurityException.class)
  public void testFailedGetPrivateKey() throws Exception {    
    final DefaultPkcs11Configuration conf = new DefaultPkcs11Configuration(getAbsolutePath("cfg1.txt"));
    conf.setBaseProviderName(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
    conf.afterPropertiesSet();

    conf.getPrivateKeyProvider().get(conf.getProvider(), ALIAS, "wrong-pin".toCharArray());
  }  
  
  @Test
  public void testMissingCredential() throws Exception {    
    final DefaultPkcs11Configuration conf = new DefaultPkcs11Configuration(getAbsolutePath("cfg1.txt"));
    conf.setBaseProviderName(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
    conf.afterPropertiesSet();

    PkiCredential cred = conf.getCredentialProvider().get(conf.getProvider(), "not-found", PIN);
    Assert.assertNull(cred);
  }
  
  @Test(expected = SecurityException.class)
  public void testFailedGetCredential() throws Exception {    
    final DefaultPkcs11Configuration conf = new DefaultPkcs11Configuration(getAbsolutePath("cfg1.txt"));
    conf.setBaseProviderName(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
    conf.afterPropertiesSet();

    conf.getCredentialProvider().get(conf.getProvider(), ALIAS, "bad-pin".toCharArray());
  }
  
  @Test
  public void testNoCertInCredential() throws Exception {    
    MockSunPkcs11Provider.MockedPkcs11ResourceHolder.getInstance().setMockNoCertificate(true);
    final DefaultPkcs11Configuration conf = new DefaultPkcs11Configuration(getAbsolutePath("cfg1.txt"));
    conf.setBaseProviderName(MockSunPkcs11Provider.PROVIDER_BASE_NAME);
    conf.afterPropertiesSet();

    PkiCredential cred = conf.getCredentialProvider().get(conf.getProvider(), ALIAS, PIN);
    Assert.assertNull(cred.getCertificate());
    Assert.assertNotNull(cred.getPrivateKey());
  }

  private static String getAbsolutePath(final String resource) throws IOException {
    return (new ClassPathResource(resource)).getFile().getAbsolutePath();
  }

}
