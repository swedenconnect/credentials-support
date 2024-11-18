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
package se.swedenconnect.security.credential;

import org.cryptacular.io.ClassPathResource;
import org.cryptacular.io.Resource;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.mockito.stubbing.Answer;
import se.swedenconnect.security.credential.factory.KeyStoreFactory;
import se.swedenconnect.security.credential.pkcs11.FilePkcs11Configuration;
import se.swedenconnect.security.credential.pkcs11.MockSunPkcs11Provider;
import se.swedenconnect.security.credential.pkcs11.Pkcs11CredentialTest;
import se.swedenconnect.security.credential.pkcs11.Pkcs11KeyStoreReloader;
import se.swedenconnect.security.credential.utils.X509Utils;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test cases for KeyStoreCredential.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class KeyStoreCredentialTest {

  private final static char[] PW = "secret".toCharArray();
  private final static String ALIAS = "test";

  private final KeyStore keyStore;
  private final PrivateKey privateKey;
  private final X509Certificate cert;
  private final X509Certificate cert2;

  public KeyStoreCredentialTest() throws Exception {
    try (final InputStream is = new ClassPathResource("rsa1.jks").getInputStream()) {
      this.keyStore = KeyStoreFactory.loadKeyStore(is, PW, null, null);
    }
    this.cert = (X509Certificate) this.keyStore.getCertificate(ALIAS);
    this.privateKey = (PrivateKey) this.keyStore.getKey(ALIAS, PW);

    final Resource res = new ClassPathResource("rsa2.crt");
    try (final InputStream is = res.getInputStream()) {
      this.cert2 = X509Utils.decodeCertificate(is);
    }
  }

  @Test
  void testExtraCerts() {
    assertDoesNotThrow(() -> new KeyStoreCredential(this.keyStore, ALIAS, PW, List.of(this.cert)));
    final IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
        new KeyStoreCredential(this.keyStore, ALIAS, PW, List.of(this.cert2)));
    assertEquals("Public key from entity certificate and private key do not make up a valid key pair", ex.getMessage());

    final IllegalArgumentException ex2 = assertThrows(IllegalArgumentException.class, () ->
        new KeyStoreCredential(this.keyStore, ALIAS, PW, List.of()));
    assertEquals("certificateChain must not be empty", ex2.getMessage());
  }

  @Test
  void testKeyStore() throws Exception {
    final KeyStoreCredential cred = new KeyStoreCredential(this.keyStore, ALIAS, PW);
    assertNotNull(cred.getKeyStore());
  }

  @Test
  void testDefaultName() throws Exception {
    final KeyStoreCredential cred = new KeyStoreCredential(this.keyStore, ALIAS, PW);

    assertEquals("RSA-" + ALIAS, cred.getName());
    assertNull(cred.getTestFunction());
  }

  @Test
  public void testDefaultNamePkcs11() throws Exception {
    final KeyStore mockedKeyStore = Mockito.mock(KeyStore.class);
    Mockito.when(mockedKeyStore.getType()).thenReturn("PKCS11");
    Mockito.when(mockedKeyStore.getKey(Mockito.any(), Mockito.any())).thenReturn(this.privateKey);
    Mockito.when(mockedKeyStore.getCertificate(Mockito.any())).thenReturn(this.cert);
    Mockito.when(mockedKeyStore.getCertificateChain(Mockito.any())).thenReturn(null);

    final Provider mockedProvider = Mockito.mock(Provider.class);
    Mockito.when(mockedKeyStore.getProvider()).thenReturn(mockedProvider);
    Mockito.when(mockedProvider.getName()).thenReturn("SunPKCS11");

    final KeyStoreCredential cred = new KeyStoreCredential(mockedKeyStore, ALIAS, PW);

    final String name = cred.getName();
    assertEquals("SunPKCS11-" + ALIAS, name);
  }

  @Test
  public void testReloadNotPkcs11() throws Exception {
    final KeyStore spyKeystore = Mockito.spy(this.keyStore);
    final KeyStoreCredential cred = new KeyStoreCredential(spyKeystore, ALIAS, PW);
    cred.reload();

    // Assert that KeyStore.getKey is only called once - during init(). Reload should do nothing since
    // this is not a P11 keystore ...
    //
    Mockito.verify(spyKeystore, Mockito.times(1)).getKey(Mockito.any(), Mockito.any());
  }

  @Test
  public void testReloadPkcs11() throws Exception {
    try {
      initPkcs11Mock();

      final String path = Pkcs11CredentialTest.getAbsolutePath("cfg1.txt");
      final FilePkcs11Configuration conf = new FilePkcs11Configuration(path, MockSunPkcs11Provider.PROVIDER_BASE_NAME);
      conf.init();

      final KeyStore p11KeyStore = KeyStoreFactory.loadPkcs11KeyStore(conf, PW);
      final KeyStore spyKeystore = Mockito.spy(p11KeyStore);

      final KeyStoreCredential cred = new KeyStoreCredential(spyKeystore, ALIAS, PW);
      cred.setName("mock");
      cred.setReloader(new Pkcs11KeyStoreReloader(PW));

      assertNotNull(cred.getTestFunction());

      Mockito.verify(spyKeystore, Mockito.times(1)).getKey(Mockito.any(), Mockito.any());

      Mockito.doAnswer((Answer<Object>) invocation -> null).when(spyKeystore).load(Mockito.any(), Mockito.any());

      cred.reload();

      // Assert that the KeyStore.getKey is called twice (once in init() and once in reload()).
      //
      Mockito.verify(spyKeystore, Mockito.times(2)).getKey(Mockito.any(), Mockito.any());
    }
    finally {
      cleanupPkcs11Mock();
    }
  }

  public static void initPkcs11Mock() {
    Security.insertProviderAt(new MockSunPkcs11Provider(), 1);

    // We let rsa1.jks simulate our PKCS#11 device
    MockSunPkcs11Provider.MockedPkcs11ResourceHolder.getInstance().setResource(new ClassPathResource("rsa1.jks"));
  }

  public static void cleanupPkcs11Mock() {
    Security.removeProvider(MockSunPkcs11Provider.PROVIDER_BASE_NAME);

    final Provider[] providers = Security.getProviders();
    for (final Provider p : providers) {
      if (p.getName().contains(MockSunPkcs11Provider.PROVIDER_BASE_NAME)) {
        Security.removeProvider(p.getName());
      }
    }

    MockSunPkcs11Provider.MockedPkcs11ResourceHolder.getInstance().setResource(null);
    MockSunPkcs11Provider.MockedPkcs11ResourceHolder.getInstance().setMockNoCertificate(false);
  }

}
