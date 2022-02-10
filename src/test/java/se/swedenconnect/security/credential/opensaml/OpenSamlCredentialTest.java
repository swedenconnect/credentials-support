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
package se.swedenconnect.security.credential.opensaml;

import java.security.KeyStore;

import org.junit.Assert;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;

import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.KeyStoreFactoryBean;

/**
 * Test cases for X509Credential.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class OpenSamlCredentialTest {
  
  private KeyStore keyStore;
  
  public OpenSamlCredentialTest() throws Exception {
    KeyStoreFactoryBean factory = new KeyStoreFactoryBean(new ClassPathResource("rsa1.jks"), "secret".toCharArray());
    factory.afterPropertiesSet();
    this.keyStore = factory.getObject();
  }
    
  @Test
  public void testInitKeyAndCertificate() throws Exception {
    PkiCredential _cred = new KeyStoreCredential(this.keyStore, "test", "secret".toCharArray());    
    
    final OpenSamlCredential cred = new OpenSamlCredential(_cred.getCertificate(), _cred.getPrivateKey());
    Assert.assertNotNull(cred.getEntityCertificate());
    Assert.assertNotNull(cred.getPrivateKey());
    Assert.assertNotNull(cred.getPublicKey());
  }
  
  @Test
  public void testInitKeyPairCredential() throws Exception {
    KeyStoreCredential _cred = new KeyStoreCredential(this.keyStore, "test", "secret".toCharArray());
    _cred.init();
    
    final OpenSamlCredential cred = new OpenSamlCredential(_cred);
    Assert.assertNotNull(cred.getEntityCertificate());
    Assert.assertNotNull(cred.getPrivateKey());
    Assert.assertNotNull(cred.getPublicKey());
  }
  
  @Test
  public void testInitDefaultAndSetter() throws Exception {
    KeyStoreCredential _cred = new KeyStoreCredential(this.keyStore, "test", "secret".toCharArray());
    _cred.init();
    
    final OpenSamlCredential cred = new OpenSamlCredential();
    cred.setCredential(_cred);
    Assert.assertNotNull(cred.getEntityCertificate());
    Assert.assertNotNull(cred.getPrivateKey());
    Assert.assertNotNull(cred.getPublicKey());
  }
  
  @Test(expected = IllegalArgumentException.class)
  public void testMixedInit() throws Exception {
    PkiCredential _cred = new KeyStoreCredential(this.keyStore, "test", "secret".toCharArray());
    _cred.init();
    
    final OpenSamlCredential cred = new OpenSamlCredential(_cred);
    cred.setPrivateKey(_cred.getPrivateKey());
  }
  
  @Test
  public void testSetChain() throws Exception {
    PkiCredential _cred = new KeyStoreCredential(this.keyStore, "test", "secret".toCharArray());
    _cred.init();
    
    final OpenSamlCredential cred = new OpenSamlCredential(_cred);    
    Assert.assertTrue(cred.getEntityCertificateChain().size() == 1);
  }
  
  @Test
  public void testGetChain() throws Exception {
    PkiCredential _cred = new KeyStoreCredential(this.keyStore, "test", "secret".toCharArray());
    _cred.init();
    
    final OpenSamlCredential cred = new OpenSamlCredential(_cred);    
    Assert.assertTrue(cred.getEntityCertificateChain().size() == 1);
  }
    
}
