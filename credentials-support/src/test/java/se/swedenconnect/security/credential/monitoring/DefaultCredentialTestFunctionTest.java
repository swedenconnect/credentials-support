/*
 * Copyright 2020-2025 Sweden Connect
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

import jakarta.annotation.Nonnull;
import lombok.NonNull;
import org.cryptacular.io.ClassPathResource;
import org.cryptacular.io.Resource;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.ReloadablePkiCredential;
import se.swedenconnect.security.credential.factory.KeyStoreFactory;
import se.swedenconnect.security.credential.monitoring.DefaultCredentialMonitorBeanTest.TestCredential;

import java.io.InputStream;
import java.security.KeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;
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

  private static ReloadablePkiCredential getCredential(final String alias) {
    final char[] password = "secret".toCharArray();
    try {
      final Resource resource = new ClassPathResource("rsa-dsa-ec.jks");
      try (final InputStream is = resource.getInputStream()) {
        final KeyStore store = KeyStoreFactory.loadKeyStore(is, password, null, null);
        return new KeyStoreCredential(store, alias, password);
      }
    }
    catch (final Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  void testSigning() {
    final Function<ReloadablePkiCredential, Exception> func = new DefaultCredentialTestFunction();

    final ReloadablePkiCredential rsa = getCredential("rsa");
    Exception result = func.apply(rsa);
    assertNull(result, "Test of RSA key was not successful");

    rsa.getMetadata().setUsage(PkiCredential.Metadata.USAGE_SIGNING);
    result = func.apply(rsa);
    assertNull(result, "Test of RSA key was not successful");

    final ReloadablePkiCredential dsa = getCredential("dsa");
    result = func.apply(dsa);
    assertNull(result, "Test of DSA key was not successful");

    final ReloadablePkiCredential ec = getCredential("ec-nist");
    ec.getMetadata().setUsage(PkiCredential.Metadata.USAGE_SIGNING);
    result = func.apply(ec);
    assertNull(result, "Test of EC key was not successful");
  }

  @Test
  void testDecryption() {
    final Function<ReloadablePkiCredential, Exception> func = new DefaultCredentialTestFunction();
    final ReloadablePkiCredential rsa = getCredential("rsa");
    rsa.getMetadata().setUsage(PkiCredential.Metadata.USAGE_ENCRYPTION);

    final Exception result = func.apply(rsa);
    assertNull(result, "Test of RSA key was not successful");
  }

  @Test
  void testProviders() {
    final DefaultCredentialTestFunction func = new DefaultCredentialTestFunction();

    final ReloadablePkiCredential rsa = getCredential("rsa");
    final ReloadablePkiCredential dsa = getCredential("dsa");

    func.setProvider("SunRsaSign");
    Exception result = func.apply(rsa);
    assertNull(result, "Test of RSA key was not successful");

    // DSA should not work with SunRsaSign provider ...
    result = func.apply(dsa);
    assertNotNull(result, "Expected NoSuchAlgorithmException result");
    assertTrue(result instanceof NoSuchAlgorithmException, "Expected NoSuchAlgorithmException exception");

    // This should work ...
    func.setProvider("SUN");
    result = func.apply(dsa);
    assertNull(result, "Test of DSA key was not successful");

    // Non-existing provider ...
    func.setProvider("FooBar");
    result = func.apply(rsa);
    assertNotNull(result, "Expected NoSuchProviderException result");
    assertTrue(result instanceof NoSuchProviderException, "Expected NoSuchProviderException exception");
  }

  @Test
  void testErrors() {
    final DefaultCredentialTestFunction func = new DefaultCredentialTestFunction();

    // NPE
    Exception result = func.apply(null);
    assertNotNull(result, "Expected NPE result");
    assertTrue(result instanceof NullPointerException, "Expected NPE exception");

    // Signing failed
    func.setRsaSignatureAlgorithm("SHA256withDSA");
    result = func.apply(getCredential("rsa"));
    assertNotNull(result, "Expected KeyException result");
    assertTrue(result instanceof KeyException, "Expected KeyException exception");

    func.setDsaSignatureAlgorithm("SHA256withRSA");
    result = func.apply(getCredential("dsa"));
    assertNotNull(result, "Expected KeyException result");
    assertTrue(result instanceof KeyException, "Expected KeyException exception");

    func.setEcSignatureAlgorithm("SHA256withRSA");
    result = func.apply(getCredential("ec-nist"));
    assertNotNull(result, "Expected KeyException result");
    assertTrue(result instanceof KeyException, "Expected KeyException exception");
  }

  @Test
  void testNoPrivateKey() {
    final DefaultCredentialTestFunction func = new DefaultCredentialTestFunction();
    final TestCredential cred = new TestCredential("test");

    final Exception result = func.apply(cred);
    assertEquals(KeyException.class, result.getClass());
  }

  @Test
  void testUnknownKeyAlgorithm() {
    final PrivateKey key = Mockito.mock(PrivateKey.class);
    Mockito.when(key.getAlgorithm()).thenReturn("UNKNOWN_ALGO");

    final ReloadablePkiCredential cred = Mockito.mock(ReloadablePkiCredential.class);
    Mockito.when(cred.getPrivateKey()).thenReturn(key);
    Mockito.when(cred.getName()).thenReturn("test");
    Mockito.when(cred.getMetadata()).thenReturn(Map::of);

    final DefaultCredentialTestFunction func = new DefaultCredentialTestFunction();
    final Exception result = func.apply(cred);
    assertEquals(NoSuchAlgorithmException.class, result.getClass());
  }

  @Test
  void testFallbackOnEncryption() {
    final ReloadablePkiCredential rsa = getCredential("rsa");
    final ReloadablePkiCredential cred = Mockito.mock(ReloadablePkiCredential.class);
    Mockito.when(cred.getPrivateKey())
        .thenReturn(rsa.getPrivateKey())
        .thenThrow(new SecurityException("CKR_KEY_TYPE_INCONSISTENT"))
        .thenReturn(rsa.getPrivateKey());
    Mockito.when(cred.getName()).thenReturn("test");
    Mockito.when(cred.getMetadata()).thenReturn(rsa.getMetadata());

    // Assert that decrypt is called
    final PublicKey pk = rsa.getPublicKey();
    Mockito.when(cred.getPublicKey()).thenReturn(pk);

    final DefaultCredentialTestFunction func = new DefaultCredentialTestFunction();
    Assertions.assertNull(func.apply(cred));
    Mockito.verify(cred, Mockito.times(1)).getPublicKey();
  }

  @Test
  void testNullSettersAreIgnored() {
    final DefaultCredentialTestFunction func = new DefaultCredentialTestFunction();
    func.setDsaSignatureAlgorithm(null);
    func.setRsaSignatureAlgorithm(null);
    func.setEcSignatureAlgorithm(null);

    Exception result = func.apply(getCredential("rsa"));
    assertNull(result);

    result = func.apply(getCredential("dsa"));
    assertNull(result);

    result = func.apply(getCredential("ec-nist"));
    assertNull(result);
  }
}
