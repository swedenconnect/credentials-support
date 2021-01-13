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
package se.swedenconnect.security.credential.monitoring;

import java.security.KeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.util.function.Function;

import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.core.io.ClassPathResource;

import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.ReloadablePkiCredential;
import se.swedenconnect.security.credential.factory.KeyStoreFactoryBean;
import se.swedenconnect.security.credential.monitoring.DefaultCredentialMonitorBeanTest.TestCredential;

/**
 * Test cases for DefaultCredentialTestFunction.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultCredentialTestFunctionTest {

  /** Password for all keys. */
  private static final char[] password = "secret".toCharArray();

  /** RSA key */
  private ReloadablePkiCredential rsaCred;

  /** DSA key */
  private ReloadablePkiCredential dsaCred;

  /** EC key */
  private ReloadablePkiCredential ecCred;

  /**
   * Constructor.
   * 
   * @throws Exception
   *           for errors setting up test data
   */
  public DefaultCredentialTestFunctionTest() throws Exception {
    final KeyStoreFactoryBean factory = new KeyStoreFactoryBean(new ClassPathResource("rsa-dsa-ec.jks"), password);
    factory.afterPropertiesSet();
    final KeyStore store = factory.getObject();

    this.rsaCred = new KeyStoreCredential(store, "rsa", password);
    this.rsaCred.init();
    this.dsaCred = new KeyStoreCredential(store, "dsa", password);
    this.dsaCred.init();
    this.ecCred = new KeyStoreCredential(store, "ec", password);
    this.ecCred.init();
  }

  /**
   * Tests the DefaultCredentialTestFunction for a RSA, DSA and EC key.
   * 
   * @throws Exception
   *           for errors
   */
  @Test
  public void testCredentials() throws Exception {
    final Function<ReloadablePkiCredential, Exception> func = new DefaultCredentialTestFunction();

    Exception result = func.apply(this.rsaCred);
    Assert.assertNull("Test of RSA key was not successful", result);

    result = func.apply(this.dsaCred);
    Assert.assertNull("Test of DSA key was not successful", result);

    result = func.apply(this.ecCred);
    Assert.assertNull("Test of EC key was not successful", result);
  }

  /**
   * Testing successful and non-successful use of provider.
   * 
   * @throws Exception
   *           for errors
   */
  @Test
  public void testProviders() throws Exception {
    final DefaultCredentialTestFunction func = new DefaultCredentialTestFunction();

    func.setProvider("SunRsaSign");
    Exception result = func.apply(this.rsaCred);
    Assert.assertNull("Test of RSA key was not successful", result);

    // DSA should not work with SunRsaSign provider ...
    result = func.apply(this.dsaCred);
    Assert.assertNotNull("Expected NoSuchAlgorithmException result", result);
    Assert.assertTrue("Expected NoSuchAlgorithmException exception",
      NoSuchAlgorithmException.class.isInstance(result));

    // This should work ...
    func.setProvider("SUN");
    result = func.apply(this.dsaCred);
    Assert.assertNull("Test of DSA key was not successful", result);

    // Non-existing provider ...
    func.setProvider("FooBar");
    result = func.apply(this.rsaCred);
    Assert.assertNotNull("Expected NoSuchProviderException result", result);
    Assert.assertTrue("Expected NoSuchProviderException exception",
      NoSuchProviderException.class.isInstance(result));
  }

  /**
   * Tests error cases.
   * 
   * @throws Exception
   *           for errors.
   */
  @Test
  public void testErrors() throws Exception {
    final DefaultCredentialTestFunction func = new DefaultCredentialTestFunction();

    // NPE
    Exception result = func.apply(null);
    Assert.assertNotNull("Expected NPE result", result);
    Assert.assertTrue("Expected NPE exception", NullPointerException.class.isInstance(result));

    // Signing failed
    func.setRsaSignatureAlgorithm("SHA256withDSA");
    result = func.apply(this.rsaCred);
    Assert.assertNotNull("Expected KeyException result", result);
    Assert.assertTrue("Expected KeyException exception", KeyException.class.isInstance(result));
    
    func.setDsaSignatureAlgorithm("SHA256withRSA");
    result = func.apply(this.dsaCred);
    Assert.assertNotNull("Expected KeyException result", result);
    Assert.assertTrue("Expected KeyException exception", KeyException.class.isInstance(result));
    
    func.setEcSignatureAlgorithm("SHA256withRSA");
    result = func.apply(this.ecCred);
    Assert.assertNotNull("Expected KeyException result", result);
    Assert.assertTrue("Expected KeyException exception", KeyException.class.isInstance(result));
  }
  
  @Test
  public void testNoPrivateKey() throws Exception {
    final DefaultCredentialTestFunction func = new DefaultCredentialTestFunction();    
    final TestCredential cred = new TestCredential("test");
    
    Exception result = func.apply(cred);
    Assert.assertEquals(KeyException.class, result.getClass());
  }
  
  @Test
  public void testUnknownKeyAlgorithm() throws Exception {
    PrivateKey key = Mockito.mock(PrivateKey.class);
    Mockito.when(key.getAlgorithm()).thenReturn("UNKNOWN_ALGO");
    
    ReloadablePkiCredential cred = Mockito.mock(ReloadablePkiCredential.class);
    Mockito.when(cred.getPrivateKey()).thenReturn(key);
    Mockito.when(cred.getName()).thenReturn("test");
    
    final DefaultCredentialTestFunction func = new DefaultCredentialTestFunction();
    Exception result = func.apply(cred);
    Assert.assertEquals(NoSuchAlgorithmException.class, result.getClass());
  }
  
  @Test
  public void testNullSettersAreIgnored() throws Exception {
    final DefaultCredentialTestFunction func = new DefaultCredentialTestFunction();
    func.setDsaSignatureAlgorithm(null);
    func.setRsaSignatureAlgorithm(null);
    func.setEcSignatureAlgorithm(null);
    
    Exception result = func.apply(this.rsaCred);
    Assert.assertNull(result);

    result = func.apply(this.dsaCred);
    Assert.assertNull(result);

    result = func.apply(this.ecCred);
    Assert.assertNull(result);
  }
}
