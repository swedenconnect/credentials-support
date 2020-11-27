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
package se.swedenconnect.security.credential.opensaml;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

import org.junit.Assert;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;

import se.swedenconnect.security.credential.KeyPairCredential;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.factory.KeyStoreFactoryBean;

/**
 * Test cases for X509Credential.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class X509CredentialTest {
  
  private KeyStore keyStore;
  
  public X509CredentialTest() throws Exception {
    KeyStoreFactoryBean factory = new KeyStoreFactoryBean(new ClassPathResource("rsa1.jks"), "secret".toCharArray());
    factory.afterPropertiesSet();
    this.keyStore = factory.getObject();
  }
  
  @Test
  public void testInitDefaultConstructor() throws Exception {
    CounterCallback cb = new CounterCallback();
    KeyPairCredential _cred = new KeyStoreCredentialExt(this.keyStore, "test", "secret".toCharArray(), cb);
    
    final X509Credential cred = new X509Credential();
    Assert.assertNull(cred.getEntityCertificate());
    Assert.assertNull(cred.getPrivateKey());
    Assert.assertNull(cred.getPublicKey());
    
    try {
      cred.afterPropertiesSet();
      Assert.fail("Expected exception because the object is not completely instantiated");
    }
    catch (Exception e) {      
    }
    
    cred.setPrivateKey(_cred.getPrivateKey());
    cred.setEntityCertificate(_cred.getCertificate());
    Assert.assertNotNull(cred.getEntityCertificate());
    Assert.assertNotNull(cred.getPrivateKey());
    Assert.assertNotNull(cred.getPublicKey());
    
    cred.afterPropertiesSet();
    
    Assert.assertNull(cred.getName());
    
    // Test that reloading doesn't work if applied to the X509Credential
    cred.reload();
    Assert.assertEquals(0, cb.counter());
  }
  
  @Test
  public void testInitKeyAndCertificate() throws Exception {
    CounterCallback cb = new CounterCallback();
    KeyPairCredential _cred = new KeyStoreCredentialExt(this.keyStore, "test", "secret".toCharArray(), cb);
    
    final X509Credential cred = new X509Credential(_cred.getCertificate(), _cred.getPrivateKey());
    Assert.assertNotNull(cred.getEntityCertificate());
    Assert.assertNotNull(cred.getPrivateKey());
    Assert.assertNotNull(cred.getPublicKey());
    cred.afterPropertiesSet();
    
    cred.setName("test");
    Assert.assertEquals("test", cred.getName());
    
    // Test that reloading doesn't work if applied to the X509Credential
    cred.reload();
    Assert.assertEquals(0, cb.counter());
  }
  
  @Test
  public void testInitKeyPairCredential() throws Exception {
    CounterCallback cb = new CounterCallback();
    KeyStoreCredential _cred = new KeyStoreCredentialExt(this.keyStore, "test", "secret".toCharArray(), cb);
    _cred.setName("test");
    
    final X509Credential cred = new X509Credential(_cred);
    Assert.assertNotNull(cred.getEntityCertificate());
    Assert.assertNotNull(cred.getPrivateKey());
    Assert.assertNotNull(cred.getPublicKey());
    Assert.assertEquals("test", cred.getName());
    cred.afterPropertiesSet();

    // It should be possible to change the name after we initialized
    cred.setName("test2");
    Assert.assertEquals("test2", cred.getName());
    
    // Test that reloading works if applied to the X509Credential since we are wrapping a KeyPairCredential
    cred.reload();
    Assert.assertEquals(1, cb.counter());
    cred.reload();
    Assert.assertEquals(2, cb.counter());
  }
  
  /**
   * For testing reloading
   */
  private static class KeyStoreCredentialExt extends KeyStoreCredential {
    
    private CounterCallback reloadCounter;

    public KeyStoreCredentialExt(final KeyStore keyStore, final String alias, final char[] keyPassword, final CounterCallback reloadCounter)
        throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
      super(keyStore, alias, keyPassword);
      this.reloadCounter = reloadCounter;
    }

    @Override
    public void reload() throws SecurityException {
      this.reloadCounter.called();
    }
    
  }
  
  private static class CounterCallback {
    private int counter = 0;
    
    public void called() {
      counter++;
    }
    
    public int counter() {
      return this.counter;
    }
  }

}
