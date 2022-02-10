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
package se.swedenconnect.security.credential;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.junit.Assert;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;

import se.swedenconnect.security.credential.factory.KeyStoreFactoryBean;

/**
 * Test cases for BasicCredential.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class BasicCredentialTest {
  
  private PrivateKey privateKey;
  private X509Certificate cert;
  
  public BasicCredentialTest() throws Exception {
    KeyStoreFactoryBean factory = new KeyStoreFactoryBean(new ClassPathResource("rsa1.jks"), "secret".toCharArray());
    factory.afterPropertiesSet();
    KeyStore keyStore = factory.getObject();
    this.cert = (X509Certificate) keyStore.getCertificate("test");
    this.privateKey = (PrivateKey) keyStore.getKey("test", "secret".toCharArray());
  }

  @Test
  public void testSetters1() throws Exception {
    final BasicCredential cred = new BasicCredential();
    cred.setPrivateKey(this.privateKey);
    cred.setCertificate(this.cert);
    cred.init();
    Assert.assertNotNull(cred.getPrivateKey());
    Assert.assertNotNull(cred.getPublicKey());
    Assert.assertNotNull(cred.getCertificate());
    Assert.assertNotNull(cred.getName());
  }
  
  @Test
  public void testSetters2() throws Exception {
    final BasicCredential cred = new BasicCredential();
    cred.setPrivateKey(this.privateKey);
    cred.setCertificate(new ClassPathResource("rsa1.crt"));
    cred.init();
    Assert.assertNotNull(cred.getPrivateKey());
    Assert.assertNotNull(cred.getPublicKey());
    Assert.assertNotNull(cred.getCertificate());
    Assert.assertNotNull(cred.getName());
  }
  
  @Test
  public void testSetters3() throws Exception {
    final BasicCredential cred = new BasicCredential();
    cred.setPrivateKey(this.privateKey);
    cred.setPublicKey(this.cert.getPublicKey());
    cred.init();
    Assert.assertNotNull(cred.getPrivateKey());
    Assert.assertNotNull(cred.getPublicKey());
    Assert.assertNull(cred.getCertificate());
    Assert.assertNotNull(cred.getName());
  }
  
  @Test(expected = IllegalArgumentException.class)
  public void testDefaultConstructorMissingKeyAndCert() throws Exception {
    final BasicCredential cred = new BasicCredential();
    cred.init();
  }
  
  @Test(expected = IllegalArgumentException.class)
  public void testDefaultConstructorMissingPublicKey() throws Exception {
    final BasicCredential cred = new BasicCredential();
    cred.setPrivateKey(this.privateKey);
    cred.init();
  }
  
  @Test(expected = IllegalArgumentException.class)
  public void testDefaultConstructorMissingPrivateKey() throws Exception {
    final BasicCredential cred = new BasicCredential();
    cred.setCertificate(this.cert);
    cred.init();
  }
  
  @Test
  public void testCertAndKeyConstructor() throws Exception {
    final BasicCredential cred = new BasicCredential(this.cert, this.privateKey);
    cred.afterPropertiesSet();
    
    Assert.assertNotNull(cred.getPrivateKey());
    Assert.assertNotNull(cred.getPublicKey());
    Assert.assertNotNull(cred.getCertificate());
    Assert.assertNotNull(cred.getName());
  }
  
  @Test
  public void testCertResourceAndKeyConstructor() throws Exception {
    final BasicCredential cred = new BasicCredential(new ClassPathResource("rsa1.crt"), this.privateKey);
    cred.afterPropertiesSet();
    
    Assert.assertNotNull(cred.getPrivateKey());
    Assert.assertNotNull(cred.getPublicKey());
    Assert.assertNotNull(cred.getCertificate());
    Assert.assertNotNull(cred.getName());
  }
  
  @Test(expected = CertificateException.class)
  public void testBadSetCertificateResource() throws Exception {
    final BasicCredential cred = new BasicCredential();
    cred.setPrivateKey(this.privateKey);
    // This is not a certificate ...
    cred.setCertificate(new ClassPathResource("rsa1.jks"));
  }
  
  @Test(expected = CertificateException.class)
  public void testMissingSetCertificateResource() throws Exception {
    final BasicCredential cred = new BasicCredential();
    cred.setPrivateKey(this.privateKey);
    // This is not a certificate ...
    cred.setCertificate(new ClassPathResource("rsaXX.crt"));
  }

  @Test(expected = IllegalArgumentException.class)
  public void testIllegalSetPublicKey() throws Exception {
    final BasicCredential cred = new BasicCredential(this.cert, this.privateKey);
    cred.init();
    cred.setPublicKey(this.cert.getPublicKey());
  }
  
  @Test(expected = IllegalArgumentException.class)
  public void testIllegalSetCertificate() throws Exception {
    final BasicCredential cred = new BasicCredential(this.cert.getPublicKey(), this.privateKey);
    cred.init();
    cred.setCertificate(this.cert);
  }
  
  @Test(expected = IllegalArgumentException.class)
  public void testIllegalSetCertificate2() throws Exception {
    final BasicCredential cred = new BasicCredential(this.cert.getPublicKey(), this.privateKey);
    cred.init();
    cred.setCertificate(new ClassPathResource("rsa1.crt"));
  }
  
  @Test
  public void testSetName() throws Exception {
    final BasicCredential cred = new BasicCredential(this.cert, this.privateKey);
    cred.setName("TEST");
    cred.init();
    
    Assert.assertEquals("TEST", cred.getName());
  }
  
  @Test
  public void testDefaultNameNoSet() throws Exception {
    final BasicCredential cred = new BasicCredential();
    final String name = cred.getName();
    Assert.assertTrue(name.startsWith("BasicCredential-"));
  }
  
  @Test
  public void testDefaultNameCertSet() throws Exception {
    final BasicCredential cred = new BasicCredential(this.cert, this.privateKey);
    final String name = cred.getName();
    Assert.assertTrue(name.contains("CN="));
  }
  
  @Test
  public void testDefaultNamePubKeySet() throws Exception {
    final BasicCredential cred = new BasicCredential(this.cert.getPublicKey(), this.privateKey);
    final String name = cred.getName();
    Assert.assertTrue(name.startsWith("RSA-"));
  }
  
  @Test
  public void testDestroy() throws Exception {
    final BasicCredential cred = new BasicCredential(this.cert.getPublicKey(), this.privateKey);
    cred.init();
    
    // Does nothing - but we want 100% test coverage ...
    cred.destroy();
  }

}
