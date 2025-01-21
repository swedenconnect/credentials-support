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
package se.swedenconnect.security.credential.pkcs11;

import jakarta.annotation.Nonnull;
import org.cryptacular.io.ClassPathResource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import se.swedenconnect.security.credential.factory.KeyStoreFactory;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;

/**
 * Test cases for {@link Pkcs11Credential}, {@link SunPkcs11PrivateKeyAccessor} and
 * {@link SunPkcs11CertificatesAccessor}.
 *
 * @author Martin Lindström
 */
public class Pkcs11CredentialTest {

  private final static char[] PIN = "secret".toCharArray();
  private final static String ALIAS = "test";

  private static final String LIBRARY = "/opt/foo/lib/libpkcs11.so";
  private static final String NAME = "mocked";

  private final KeyStore keyStore;
  private final X509Certificate cert;

  @BeforeEach
  public void init() {
    Security.insertProviderAt(new MockSunPkcs11Provider(), 1);

    // We let rsa1.jks simulate our PKCS#11 device
    MockSunPkcs11Provider.MockedPkcs11ResourceHolder.getInstance().setResource(new ClassPathResource("rsa1.jks"));
  }

  @AfterEach
  public void after() {
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

  public Pkcs11CredentialTest() throws Exception {
    try (final InputStream stream = new ClassPathResource("rsa1.jks").getInputStream()) {
      this.keyStore = KeyStoreFactory.loadKeyStore(stream, "secret".toCharArray(), null, null);
    }
    this.cert = (X509Certificate) this.keyStore.getCertificate(ALIAS);
  }

  @Test
  void testCreateAndUse() {
    final FilePkcs11Configuration configuration = new TestFilePkcs11Configuration(getAbsolutePath("cfg1.txt"));
    configuration.init();
    final String providerName = configuration.getProvider().getName();

    final Pkcs11Credential credential = new Pkcs11Credential(configuration, ALIAS, PIN,
        new SunPkcs11PrivateKeyAccessor(), new SunPkcs11CertificatesAccessor());

    Assertions.assertEquals("%s-%s".formatted(providerName, ALIAS), credential.getName());
    // TODO: more
  }

  public static String getAbsolutePath(final String resource) {
    final String p = resource.startsWith("/") ? "" : "/";
    return System.getProperty("user.dir") + "/src/test/resources" + p + resource;
  }

  // For testing with mocked provider
  private static class TestFilePkcs11Configuration extends FilePkcs11Configuration {

    public TestFilePkcs11Configuration(@Nonnull final String configurationFile) {
      super(configurationFile, MockSunPkcs11Provider.PROVIDER_BASE_NAME);
    }

    @Nonnull
    @Override
    public String getConfigurationData() {
      return super.getConfigurationData();
    }
  }

}
