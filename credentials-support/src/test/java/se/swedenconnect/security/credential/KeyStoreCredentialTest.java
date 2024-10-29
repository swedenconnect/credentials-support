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

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.mockito.stubbing.Answer;
import org.springframework.core.io.ClassPathResource;
import se.swedenconnect.security.credential.factory.KeyStoreFactory;
import se.swedenconnect.security.credential.pkcs11.FilePkcs11Configuration;
import se.swedenconnect.security.credential.pkcs11.MockSunPkcs11Provider;
import se.swedenconnect.security.credential.pkcs11.Pkcs11CredentialTest;

import javax.annotation.Nonnull;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;

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

  public KeyStoreCredentialTest() throws Exception {
    try (final InputStream is = new ClassPathResource("rsa1.jks").getInputStream()) {
      this.keyStore = KeyStoreFactory.loadKeyStore(is, PW, null, null);
    }
    this.cert = (X509Certificate) this.keyStore.getCertificate(ALIAS);
    this.privateKey = (PrivateKey) this.keyStore.getKey(ALIAS, PW);
  }

  @Test
  void testDefaultName() throws Exception {
    final KeyStoreCredential cred = new KeyStoreCredential(this.keyStore, ALIAS, PW);

    assertEquals("RSA-" + ALIAS, cred.getName());
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
      final TestFilePkcs11Configuration conf = new TestFilePkcs11Configuration(path);
      conf.init();

      final KeyStore p11KeyStore = KeyStoreFactory.loadPkcs11KeyStore(conf, PW);
      final KeyStore spyKeystore = Mockito.spy(p11KeyStore);

      final KeyStoreCredential cred = new KeyStoreCredential(spyKeystore, ALIAS, PW);
      cred.setName("mock");

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

  private static void initPkcs11Mock() {
    Security.insertProviderAt(new MockSunPkcs11Provider(), 1);

    // We let rsa1.jks simulate our PKCS#11 device
    MockSunPkcs11Provider.MockedPkcs11ResourceHolder.getInstance().setResource(new ClassPathResource("rsa1.jks"));
  }

  private static void cleanupPkcs11Mock() {
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

  // For testing with mocked provider
  private static class TestFilePkcs11Configuration extends FilePkcs11Configuration {

    public TestFilePkcs11Configuration(@Nonnull final String configurationFile) {
      super(configurationFile);
    }

    @Override
    protected String getBaseProviderName() {
      return MockSunPkcs11Provider.PROVIDER_BASE_NAME;
    }

    @Nonnull
    @Override
    public String getConfigurationData() {
      return super.getConfigurationData();
    }
  }

}
