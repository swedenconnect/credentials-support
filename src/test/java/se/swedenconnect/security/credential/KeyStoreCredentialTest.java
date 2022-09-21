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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.core.io.ClassPathResource;

import se.swedenconnect.security.credential.factory.KeyStoreFactoryBean;

/**
 * Test cases for KeyStoreCredential.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class KeyStoreCredentialTest {

  private final static char[] PW = "secret".toCharArray();
  private final static String ALIAS = "test";

  private KeyStore keyStore;
  private PrivateKey privateKey;
  private X509Certificate cert;

  public KeyStoreCredentialTest() throws Exception {
    KeyStoreFactoryBean factory = new KeyStoreFactoryBean(new ClassPathResource("rsa1.jks"), PW);
    factory.afterPropertiesSet();
    this.keyStore = factory.getObject();
    this.cert = (X509Certificate) this.keyStore.getCertificate(ALIAS);
    this.privateKey = (PrivateKey) this.keyStore.getKey(ALIAS, PW);
  }

  @Test
  public void testDefaultConstructorNoSetters() throws Exception {
    assertThrows(IllegalArgumentException.class, () -> {
      final KeyStoreCredential cred = new KeyStoreCredential();
      cred.afterPropertiesSet();
    });
  }

  @Test
  public void testSettersWithKeyStore() throws Exception {
    final KeyStoreCredential cred = new KeyStoreCredential();
    cred.setKeyStore(this.keyStore);
    cred.setAlias(ALIAS);
    cred.setKeyPassword(PW);
    cred.init();

    assertNotNull(cred.getPrivateKey());
    assertNotNull(cred.getPublicKey());
    assertNotNull(cred.getCertificate());
    assertEquals(ALIAS, cred.getName());
  }

  @Test
  public void testConstructorWithKeyStore() throws Exception {
    final KeyStoreCredential cred = new KeyStoreCredential(this.keyStore, ALIAS, PW);
    cred.init();

    assertNotNull(cred.getPrivateKey());
    assertNotNull(cred.getPublicKey());
    assertNotNull(cred.getCertificate());
    assertEquals(ALIAS, cred.getName());
  }

  @Test
  public void testConstructorWithResource() throws Exception {
    KeyStoreCredential cred = new KeyStoreCredential(
      new ClassPathResource("rsa1.jks"), PW, ALIAS, PW);
    cred.init();

    assertNotNull(cred.getPrivateKey());
    assertNotNull(cred.getPublicKey());
    assertNotNull(cred.getCertificate());
    assertEquals(ALIAS, cred.getName());

    cred = new KeyStoreCredential(
      new ClassPathResource("rsa1.jks"), "JKS", PW, ALIAS, PW);
    cred.init();

    assertNotNull(cred.getPrivateKey());
    assertNotNull(cred.getPublicKey());
    assertNotNull(cred.getCertificate());
    assertEquals(ALIAS, cred.getName());

    cred = new KeyStoreCredential(
      new ClassPathResource("rsa1.jks"), "JKS", "SUN", PW, ALIAS, PW);
    cred.init();

    assertNotNull(cred.getPrivateKey());
    assertNotNull(cred.getPublicKey());
    assertNotNull(cred.getCertificate());
    assertEquals(ALIAS, cred.getName());
  }

  @Test
  public void testSettersWithAll() throws Exception {
    KeyStoreCredential cred = new KeyStoreCredential();
    cred.setResource(new ClassPathResource("rsa1.jks"));
    cred.setPassword(PW);
    cred.setAlias(ALIAS);
    cred.setKeyPassword(PW);
    cred.init();

    assertNotNull(cred.getPrivateKey());
    assertNotNull(cred.getPublicKey());
    assertNotNull(cred.getCertificate());
    assertEquals(ALIAS, cred.getName());

    // Call setters in different orders to make sure that the underlying keyStoreFactory is
    // set up in all cases ...
    //
    cred = new KeyStoreCredential();
    cred.setPassword(PW);
    cred.setAlias(ALIAS);
    cred.setKeyPassword(PW);
    cred.setResource(new ClassPathResource("rsa1.jks"));
    cred.init();

    assertNotNull(cred.getPrivateKey());
    assertNotNull(cred.getPublicKey());
    assertNotNull(cred.getCertificate());
    assertEquals(ALIAS, cred.getName());

    cred = new KeyStoreCredential();
    cred.setAlias(ALIAS);
    cred.setKeyPassword(PW);
    cred.setResource(new ClassPathResource("rsa1.jks"));
    cred.setPassword(PW);
    cred.init();

    assertNotNull(cred.getPrivateKey());
    assertNotNull(cred.getPublicKey());
    assertNotNull(cred.getCertificate());
    assertEquals(ALIAS, cred.getName());

    cred = new KeyStoreCredential();
    cred.setKeyPassword(PW);
    cred.setResource(new ClassPathResource("rsa1.jks"));
    cred.setPassword(PW);
    cred.setAlias(ALIAS);
    cred.init();

    assertNotNull(cred.getPrivateKey());
    assertNotNull(cred.getPublicKey());
    assertNotNull(cred.getCertificate());
    assertEquals(ALIAS, cred.getName());

    cred = new KeyStoreCredential();
    cred.setType("JKS");
    cred.setKeyPassword(PW);
    cred.setResource(new ClassPathResource("rsa1.jks"));
    cred.setPassword(PW);
    cred.setAlias(ALIAS);
    cred.init();

    assertNotNull(cred.getPrivateKey());
    assertNotNull(cred.getPublicKey());
    assertNotNull(cred.getCertificate());
    assertEquals(ALIAS, cred.getName());

    cred = new KeyStoreCredential();
    cred.setProvider("SUN");
    cred.setPkcs11Configuration("/dummy/path");
    cred.setType("JKS");
    cred.setKeyPassword(PW);
    cred.setResource(new ClassPathResource("rsa1.jks"));
    cred.setPassword(PW);
    cred.setAlias(ALIAS);
    cred.init();

    assertNotNull(cred.getPrivateKey());
    assertNotNull(cred.getPublicKey());
    assertNotNull(cred.getCertificate());
    assertEquals(ALIAS, cred.getName());

    cred = new KeyStoreCredential();
    cred.setPkcs11Configuration("/dummy/path");
    cred.setType("JKS");
    cred.setKeyPassword(PW);
    cred.setResource(new ClassPathResource("rsa1.jks"));
    cred.setPassword(PW);
    cred.setAlias(ALIAS);
    cred.setProvider("SUN");
    cred.init();

    assertNotNull(cred.getPrivateKey());
    assertNotNull(cred.getPublicKey());
    assertNotNull(cred.getCertificate());
    assertEquals(ALIAS, cred.getName());
  }

  @Test
  public void testMultipleInit() throws Exception {
    final KeyStoreCredential cred = new KeyStoreCredential(
      new ClassPathResource("rsa1.jks"), PW, ALIAS, PW);
    cred.init();

    assertNotNull(cred.getPrivateKey());
    assertNotNull(cred.getPublicKey());
    assertNotNull(cred.getCertificate());
    assertEquals(ALIAS, cred.getName());

    cred.init();
    assertNotNull(cred.getPrivateKey());
    assertNotNull(cred.getPublicKey());
    assertNotNull(cred.getCertificate());
    assertEquals(ALIAS, cred.getName());
  }

  @Test
  public void testExplicitAssignedCertificate() throws Exception {
    final KeyStoreCredential cred = new KeyStoreCredential(
      new ClassPathResource("rsa1.jks"), PW, ALIAS, PW);
    cred.setCertificate(this.cert);
    cred.init();

    assertNotNull(cred.getPrivateKey());
    assertNotNull(cred.getPublicKey());
    assertNotNull(cred.getCertificate());
    assertEquals(ALIAS, cred.getName());
  }

  @Test
  public void testExplicitAssignedCertificateResource() throws Exception {
    final KeyStoreCredential cred = new KeyStoreCredential(
      new ClassPathResource("rsa1.jks"), PW, ALIAS, PW);
    cred.setCertificate(new ClassPathResource("rsa1.crt"));
    cred.init();

    assertNotNull(cred.getPrivateKey());
    assertNotNull(cred.getPublicKey());
    assertNotNull(cred.getCertificate());
    assertEquals(ALIAS, cred.getName());
  }

  @Test
  public void illegalSetPublicKey() throws Exception {
    assertThrows(IllegalArgumentException.class, () -> {
      final KeyStoreCredential cred = new KeyStoreCredential();
      cred.setPublicKey(this.cert.getPublicKey());
    });
  }

  @Test
  public void illegalSetPrivateKey() throws Exception {
    assertThrows(IllegalArgumentException.class, () -> {
      final KeyStoreCredential cred = new KeyStoreCredential();
      cred.setPrivateKey(this.privateKey);
    });
  }

  @Test
  public void missingAlias() throws Exception {
    assertThrows(IllegalArgumentException.class, () -> {
      final KeyStoreCredential cred = new KeyStoreCredential(
        new ClassPathResource("rsa1.jks"), PW, null, PW);
      cred.init();
    });
  }

  @Test
  public void testSamePassword() throws Exception {
    final KeyStoreCredential cred = new KeyStoreCredential(
      new ClassPathResource("rsa1.jks"), PW, ALIAS, null);
    cred.init();

    assertNotNull(cred.getPrivateKey());
    assertNotNull(cred.getPublicKey());
    assertNotNull(cred.getCertificate());
    assertEquals(ALIAS, cred.getName());
  }

  @Test
  public void missingKeyPassword() throws Exception {
    assertThrows(UnrecoverableKeyException.class, () -> {
      final KeyStoreCredential cred = new KeyStoreCredential();
      cred.setKeyStore(this.keyStore);
      cred.setAlias(ALIAS);
      cred.init();
    });
  }

  @Test
  public void notPrivateKey() throws Exception {
    assertThrows(KeyStoreException.class, () -> {
      final KeyStoreCredential cred = new KeyStoreCredential(
        new ClassPathResource("aes.jceks"), "JCEKS", "secret".toCharArray(), "aes", "secret".toCharArray());
      cred.init();
    });
  }

  @Test
  public void testDestroy() throws Exception {
    final KeyStoreCredential cred = new KeyStoreCredential();
    cred.setKeyStore(this.keyStore);
    cred.setAlias(ALIAS);
    cred.setKeyPassword(PW);
    cred.init();
    cred.destroy();

    Field pk = KeyStoreCredential.class.getDeclaredField("keyPassword");
    pk.setAccessible(true);
    Object pw = pk.get(cred);
    char[] expected = new char[PW.length];
    Arrays.fill(expected, (char) 0);
    assertArrayEquals(expected, (char[]) pw);
  }

  @Test
  public void testDestroy2() throws Exception {
    final KeyStoreCredential cred = new KeyStoreCredential();
    cred.setResource(new ClassPathResource("rsa1.jks"));
    cred.setPassword(PW);
    cred.setAlias(ALIAS);
    cred.setKeyPassword(PW);
    cred.init();
    cred.destroy();

    Field pk = KeyStoreCredential.class.getDeclaredField("password");
    pk.setAccessible(true);
    Object pw = pk.get(cred);

    Field kpk = KeyStoreCredential.class.getDeclaredField("keyPassword");
    kpk.setAccessible(true);
    Object kpw = kpk.get(cred);

    char[] expected = new char[PW.length];
    Arrays.fill(expected, (char) 0);
    assertArrayEquals(expected, (char[]) pw);
    assertArrayEquals(expected, (char[]) kpw);
  }

  @Test
  public void testDestroy3() throws Exception {
    final KeyStoreCredential cred = new KeyStoreCredential();
    cred.setResource(new ClassPathResource("rsa1.jks"));
    cred.setAlias(ALIAS);
    try {
      cred.init();
    }
    catch (Exception e) {
    }
    cred.destroy();

    Field pk = KeyStoreCredential.class.getDeclaredField("password");
    pk.setAccessible(true);
    assertNull(pk.get(cred));

    Field kpk = KeyStoreCredential.class.getDeclaredField("keyPassword");
    kpk.setAccessible(true);
    assertNull(kpk.get(cred));
  }

  @Test
  public void testAutoInit() throws Exception {
    KeyStoreCredential cred = new KeyStoreCredential(
      new ClassPathResource("rsa1.jks"), PW, ALIAS, PW);

    assertNotNull(cred.getPrivateKey());
    assertNotNull(cred.getPublicKey());
    assertNotNull(cred.getCertificate());

    cred = new KeyStoreCredential(
      new ClassPathResource("rsa1.jks"), PW, ALIAS, PW);

    assertNotNull(cred.getPublicKey());
    assertNotNull(cred.getCertificate());
    assertNotNull(cred.getPrivateKey());

    cred = new KeyStoreCredential(
      new ClassPathResource("rsa1.jks"), PW, ALIAS, PW);

    assertNotNull(cred.getCertificate());
    assertNotNull(cred.getPrivateKey());
    assertNotNull(cred.getPublicKey());
  }

  @Test
  public void testAutoInitError() throws Exception {
    assertThrows(SecurityException.class, () -> {
      KeyStoreCredential cred = new KeyStoreCredential(
        new ClassPathResource("rsa1.jks"), PW, ALIAS, "dummy".toCharArray());

      cred.getPrivateKey();
    });
  }

  @Test
  public void testAutoInitError2() throws Exception {
    assertThrows(SecurityException.class, () -> {
      KeyStoreCredential cred = new KeyStoreCredential(
        new ClassPathResource("rsa1.jks"), PW, "dummy", PW);

      cred.getCertificate();
    });
  }

  @Test
  public void testAutoInitError3() throws Exception {
    assertThrows(SecurityException.class, () -> {
      KeyStoreCredential cred = new KeyStoreCredential(
        new ClassPathResource("rsa1.jks"), PW, "dummy", PW);

      cred.getPublicKey();
    });
  }

  @Test
  public void testDefaultName() throws Exception {
    KeyStoreCredential cred = new KeyStoreCredential(
      new ClassPathResource("rsa1.jks"), PW, ALIAS, PW);
    cred.init();

    assertEquals(ALIAS, cred.getName());

    cred = new KeyStoreCredential();
    assertTrue(cred.getName().startsWith("KeyStoreCredential-"));
  }

  @Test
  public void testDefaultNamePkcs11() throws Exception {
    KeyStoreCredential cred = new KeyStoreCredential(
      new ClassPathResource("rsa1.jks"), PW, ALIAS, PW);
    cred.init();

    KeyStore mockedKeyStore = Mockito.mock(KeyStore.class);
    Provider mockedProvider = Mockito.mock(Provider.class);
    Mockito.when(mockedKeyStore.getType()).thenReturn("PKCS11");
    Mockito.when(mockedKeyStore.getProvider()).thenReturn(mockedProvider);
    Mockito.when(mockedProvider.getName()).thenReturn("SunPKCS11");

    // Install mocked keystore ...
    cred.setKeyStore(mockedKeyStore);

    String name = cred.getName();

    assertEquals("SunPKCS11-" + ALIAS, name);
  }

  @Test
  public void testReloadNotInit() throws Exception {
    assertThrows(SecurityException.class, () -> {
      KeyStoreCredential cred = new KeyStoreCredential();
      cred.reload();
    });
  }

  @Test
  public void testReloadNotPkcs11() throws Exception {
    KeyStore spyKeystore = Mockito.spy(this.keyStore);

    KeyStoreCredential cred = new KeyStoreCredential(spyKeystore, ALIAS, PW);
    cred.init();
    cred.reload();

    // Assert that KeyStore.getKey is only called once - during init(). Reload should do nothing since
    // this is not a P11 keystore ...
    //
    Mockito.verify(spyKeystore, Mockito.times(1)).getKey(Mockito.any(), Mockito.any());
  }

  @Test
  public void testReloadPkcs11() throws Exception {

    KeyStore spyKeystore = Mockito.spy(this.keyStore);

    KeyStoreCredential cred = new KeyStoreCredential(spyKeystore, ALIAS, PW);
    cred.setName("mock");
    cred.init();

    Mockito.verify(spyKeystore, Mockito.times(1)).getKey(Mockito.any(), Mockito.any());

    Mockito.doReturn("PKCS11").when(spyKeystore).getType();
    Mockito.doAnswer(new Answer<Object>() {
      @Override
      public Object answer(InvocationOnMock invocation) throws Throwable {
        return null;
      }
    }).when(spyKeystore).load(Mockito.any(), Mockito.any());

    cred.reload();

    // Assert that the KeyStore.getKey is called twice (once in init() and once in reload()).
    //
    Mockito.verify(spyKeystore, Mockito.times(2)).getKey(Mockito.any(), Mockito.any());
  }

  @Test
  public void testReloadPkcs11Error() throws Exception {
    assertThrows(KeyStoreException.class, () -> {
      KeyStore spyKeystore = Mockito.spy(this.keyStore);

      KeyStoreCredential cred = new KeyStoreCredential(spyKeystore, ALIAS, PW);
      cred.setName("mock");
      cred.init();

      Mockito.verify(spyKeystore, Mockito.times(1)).getKey(Mockito.any(), Mockito.any());

      Mockito.doReturn("PKCS11").when(spyKeystore).getType();
      Mockito.doAnswer(new Answer<Object>() {
        @Override
        public Object answer(InvocationOnMock invocation) throws Throwable {
          return null;
        }
      }).when(spyKeystore).load(Mockito.any(), Mockito.any());
      Mockito.doAnswer(i -> { throw new KeyStoreException("mock"); })
        .when(spyKeystore).getKey(Mockito.any(), Mockito.any());

      cred.reload();
    });
  }

  @Test
  public void testMissingCertificate() throws Exception {
    assertThrows(CertificateException.class, () -> {
      KeyStore spyKeystore = Mockito.spy(this.keyStore);
      Mockito.doReturn(null).when(spyKeystore).getCertificate(Mockito.any());
      Mockito.doReturn(null).when(spyKeystore).getCertificateChain(Mockito.any());

      KeyStoreCredential cred = new KeyStoreCredential(spyKeystore, ALIAS, PW);
      cred.init();
    });
  }
}
