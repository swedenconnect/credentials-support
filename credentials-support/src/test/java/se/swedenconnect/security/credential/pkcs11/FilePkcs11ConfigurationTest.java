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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.Provider;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test cases for {@link FilePkcs11Configuration} and {@link AbstractSunPkcs11Configuration}.
 *
 * @author Martin Lindström
 */
public class FilePkcs11ConfigurationTest {

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

  @Test
  void testCreate() {

    final String path = getAbsolutePath("cfg1.txt");
    final TestFilePkcs11Configuration conf = new TestFilePkcs11Configuration(path);
    conf.init();

    final Provider provider = conf.getProvider();
    assertNotNull(provider);
    assertEquals(MockSunPkcs11Provider.PROVIDER_BASE_NAME + "-Foo", provider.getName());

    assertEquals(path, conf.getConfigurationData());
    assertEquals("provider='%s', config-file='%s'"
        .formatted(MockSunPkcs11Provider.PROVIDER_BASE_NAME + "-Foo", path), conf.toString());
  }

  @Test
  void testNullConfigFile() {
    assertThrows(NullPointerException.class, () -> new TestFilePkcs11Configuration(null));
  }

  @Test
  public void testMissingFile() {
    assertThrows(IllegalArgumentException.class, () -> new TestFilePkcs11Configuration("/opt/foo/not-there.txt"));
  }

  @Test
  public void testNotFile() {
    final String path = System.getProperty("user.dir") + "/src/test/resources";
    assertThrows(IllegalArgumentException.class, () -> new TestFilePkcs11Configuration(path));
  }

  private static String getAbsolutePath(final String resource) {
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
