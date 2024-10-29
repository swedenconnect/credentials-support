/*
 * Copyright 2020-2024 Sweden Connect
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

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.core.io.ClassPathResource;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.ReloadablePkiCredential;
import se.swedenconnect.security.credential.factory.KeyStoreFactoryBean;
import se.swedenconnect.security.credential.monitoring.DefaultCredentialMonitorBeanTest.TestCredential;

import java.security.KeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
  private final ReloadablePkiCredential rsaCred;

  /** DSA key */
  private final ReloadablePkiCredential dsaCred;

  /** EC key */
  private final ReloadablePkiCredential ecCred;

  /**
   * Constructor.
   *
   * @throws Exception for errors setting up test data
   */
  public DefaultCredentialTestFunctionTest() throws Exception {
    final KeyStoreFactoryBean factory = new KeyStoreFactoryBean(new ClassPathResource("rsa-dsa-ec.jks"), password);
    factory.afterPropertiesSet();
    final KeyStore store = factory.getObject();

    this.rsaCred = new KeyStoreCredential(store, "rsa", password);
    this.dsaCred = new KeyStoreCredential(store, "dsa", password);
    this.ecCred = new KeyStoreCredential(store, "ec", password);
  }

  /**
   * Tests the DefaultCredentialTestFunction for an RSA, DSA and EC key.
   */
  @Test
  public void testCredentials() {
    final Function<ReloadablePkiCredential, Exception> func = new DefaultCredentialTestFunction();

    Exception result = func.apply(this.rsaCred);
    assertNull(result, "Test of RSA key was not successful");

    result = func.apply(this.dsaCred);
    assertNull(result, "Test of DSA key was not successful");

    result = func.apply(this.ecCred);
    assertNull(result, "Test of EC key was not successful");
  }

  /**
   * Testing successful and non-successful use of provider.
   */
  @Test
  public void testProviders() {
    final DefaultCredentialTestFunction func = new DefaultCredentialTestFunction();

    func.setProvider("SunRsaSign");
    Exception result = func.apply(this.rsaCred);
    assertNull(result, "Test of RSA key was not successful");

    // DSA should not work with SunRsaSign provider ...
    result = func.apply(this.dsaCred);
    assertNotNull(result, "Expected NoSuchAlgorithmException result");
    assertTrue(result instanceof NoSuchAlgorithmException, "Expected NoSuchAlgorithmException exception");

    // This should work ...
    func.setProvider("SUN");
    result = func.apply(this.dsaCred);
    assertNull(result, "Test of DSA key was not successful");

    // Non-existing provider ...
    func.setProvider("FooBar");
    result = func.apply(this.rsaCred);
    assertNotNull(result, "Expected NoSuchProviderException result");
    assertTrue(result instanceof NoSuchProviderException, "Expected NoSuchProviderException exception");
  }

  /**
   * Tests error cases.
   */
  @Test
  public void testErrors() {
    final DefaultCredentialTestFunction func = new DefaultCredentialTestFunction();

    // NPE
    Exception result = func.apply(null);
    assertNotNull(result, "Expected NPE result");
    assertTrue(result instanceof NullPointerException, "Expected NPE exception");

    // Signing failed
    func.setRsaSignatureAlgorithm("SHA256withDSA");
    result = func.apply(this.rsaCred);
    assertNotNull(result, "Expected KeyException result");
    assertTrue(result instanceof KeyException, "Expected KeyException exception");

    func.setDsaSignatureAlgorithm("SHA256withRSA");
    result = func.apply(this.dsaCred);
    assertNotNull(result, "Expected KeyException result");
    assertTrue(result instanceof KeyException, "Expected KeyException exception");

    func.setEcSignatureAlgorithm("SHA256withRSA");
    result = func.apply(this.ecCred);
    assertNotNull(result, "Expected KeyException result");
    assertTrue(result instanceof KeyException, "Expected KeyException exception");
  }

  @Test
  public void testNoPrivateKey() {
    final DefaultCredentialTestFunction func = new DefaultCredentialTestFunction();
    final TestCredential cred = new TestCredential("test");

    final Exception result = func.apply(cred);
    assertEquals(KeyException.class, result.getClass());
  }

  @Test
  public void testUnknownKeyAlgorithm() {
    final PrivateKey key = Mockito.mock(PrivateKey.class);
    Mockito.when(key.getAlgorithm()).thenReturn("UNKNOWN_ALGO");

    final ReloadablePkiCredential cred = Mockito.mock(ReloadablePkiCredential.class);
    Mockito.when(cred.getPrivateKey()).thenReturn(key);
    Mockito.when(cred.getName()).thenReturn("test");

    final DefaultCredentialTestFunction func = new DefaultCredentialTestFunction();
    final Exception result = func.apply(cred);
    assertEquals(NoSuchAlgorithmException.class, result.getClass());
  }

  @Test
  public void testNullSettersAreIgnored() {
    final DefaultCredentialTestFunction func = new DefaultCredentialTestFunction();
    func.setDsaSignatureAlgorithm(null);
    func.setRsaSignatureAlgorithm(null);
    func.setEcSignatureAlgorithm(null);

    Exception result = func.apply(this.rsaCred);
    assertNull(result);

    result = func.apply(this.dsaCred);
    assertNull(result);

    result = func.apply(this.ecCred);
    assertNull(result);
  }
}
