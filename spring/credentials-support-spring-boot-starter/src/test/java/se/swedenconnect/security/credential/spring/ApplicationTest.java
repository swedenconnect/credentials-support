/*
 * Copyright 2020-2026 Sweden Connect
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
package se.swedenconnect.security.credential.spring;

import org.cryptacular.io.ClassPathResource;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.Status;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import se.swedenconnect.security.credential.AbstractReloadablePkiCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.PkiCredentialCollection;
import se.swedenconnect.security.credential.ReloadablePkiCredential;
import se.swedenconnect.security.credential.bundle.CredentialBundleRegistrar;
import se.swedenconnect.security.credential.bundle.CredentialBundleRegistry;
import se.swedenconnect.security.credential.bundle.CredentialBundles;
import se.swedenconnect.security.credential.monitoring.CredentialMonitorBean;
import se.swedenconnect.security.credential.pkcs11.MockSunPkcs11Provider;
import se.swedenconnect.security.credential.spring.actuator.CredentialMonitorHealthIndicator;
import se.swedenconnect.security.credential.spring.config.SpringConfigurationResourceLoader;
import se.swedenconnect.security.credential.spring.converters.KeyStoreReferenceConverter;
import se.swedenconnect.security.credential.spring.converters.PkiCredentialReferenceConverter;
import se.swedenconnect.security.credential.spring.converters.PropertyToPrivateKeyConverter;
import se.swedenconnect.security.credential.spring.converters.PropertyToX509CertificateConverter;

import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.time.Instant;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author Martin Lindström
 */
@ExtendWith(SpringExtension.class)
@Import({ TestConfiguration.class })
@TestPropertySource(locations = "classpath:application.yml", factory = YamlPropertyLoaderFactory.class)
@EnableAutoConfiguration
@EnableScheduling
class ApplicationTest {

  @Autowired
  ApplicationContext applicationContext;

  @BeforeAll
  public static void initPkcs11() {
    // Add our mocked PKCS#11 security provider.
    Security.addProvider(new MockSunPkcs11Provider());

    // We let rsa1.jks simulate our PKCS#11 device.
    MockSunPkcs11Provider.MockedPkcs11ResourceHolder.getInstance().setResource(new ClassPathResource("test-1.jks"));
  }

  @AfterAll
  public static void resetPkcs11() {
    Security.removeProvider(MockSunPkcs11Provider.PROVIDER_BASE_NAME);

    final Provider[] providers = Security.getProviders();
    for (final Provider p : providers) {
      if (p.getName().contains(MockSunPkcs11Provider.PROVIDER_BASE_NAME)) {
        Security.removeProvider(p.getName());
      }
    }
  }

  @DisplayName("Tests that all expected beans are created")
  @Test
  void testBeans() {
    assertDoesNotThrow(() -> this.applicationContext.getBean(CredentialBundles.class));
    assertDoesNotThrow(() -> this.applicationContext.getBean(CredentialBundleRegistry.class));
    assertDoesNotThrow(
        () -> this.applicationContext.getBean("credential-monitor", CredentialMonitorHealthIndicator.class));
    assertDoesNotThrow(() -> this.applicationContext.getBean(CredentialMonitorBean.class));
    assertDoesNotThrow(() -> this.applicationContext.getBean(SpringConfigurationResourceLoader.class));
    assertDoesNotThrow(() -> this.applicationContext.getBean(CredentialBundleRegistrar.class));

    assertDoesNotThrow(() -> this.applicationContext.getBean(PropertyToX509CertificateConverter.class));
    assertDoesNotThrow(() -> this.applicationContext.getBean(PropertyToPrivateKeyConverter.class));
    assertDoesNotThrow(() -> this.applicationContext.getBean(PkiCredentialReferenceConverter.class));
    assertDoesNotThrow(() -> this.applicationContext.getBean(KeyStoreReferenceConverter.class));
    assertDoesNotThrow(() -> this.applicationContext.getBean(PkiCredentialCollection.class));
  }

  @DisplayName("Tests that converters are used")
  @Test
  void testConverters() {
    final TestObject test1 = this.applicationContext.getBean("testobject1", TestObject.class);
    assertNotNull(test1.getCredential());
    assertNotNull(test1.getKeyStore());
  }

  @DisplayName("Tests that all credentials configured are available from the CredentialsBundles bean")
  @Test
  void testCredentials() {
    final CredentialBundles bundles = this.applicationContext.getBean(CredentialBundles.class);

    final KeyStore keystore1 = bundles.getKeyStore("keystore1");
    assertEquals("JKS", keystore1.getType());

    final KeyStore p11 = bundles.getKeyStore("p11");
    assertEquals("PKCS11", p11.getType());

    final PkiCredential test1 = bundles.getCredential("test1");
    assertEquals("Test1", test1.getName());

    final PkiCredential test2 = bundles.getCredential("test2");
    assertEquals("Test2", test2.getName());

    final PkiCredential test3 = bundles.getCredential("test3");
    assertEquals("Test3", test3.getName());

    final PkiCredential test3b = bundles.getCredential("test3b");
    assertEquals("Test3b", test3b.getName());
    assertNull(test3b.getCertificate());

    final PkiCredential test4 = bundles.getCredential("test4");
    assertEquals("Test4", test4.getName());

    final PkiCredential test5 = bundles.getCredential("test5");
    assertEquals("Test5", test5.getName());

    final PkiCredential testP11 = bundles.getCredential("testP11");
    assertEquals("TestPkcs11", testP11.getName());

    final PkiCredentialCollection collection = this.applicationContext.getBean(PkiCredentialCollection.class);
    assertTrue(collection.getCredentials().size() == 2);
    assertNotNull(collection.getCredentials(c -> "Test2-x".equals(c.getName())));
    assertNotNull(collection.getCredentials(c -> "Test1".equals(c.getName())));
  }

  @DisplayName("Tests that metadata properties are assigned")
  @Test
  void testMetadata() {
    final CredentialBundles bundles = this.applicationContext.getBean(CredentialBundles.class);
    final PkiCredential test1 = bundles.getCredential("test1");

    assertEquals("123456", test1.getMetadata().getKeyId());
    assertEquals("RSA", test1.getMetadata().getProperties().get("algorithm"));
    assertEquals(Instant.parse("2024-11-15T14:08:26Z"), test1.getMetadata().getIssuedAt());
  }

  @DisplayName("Tests that monitoring and health endpoint handles test failures")
  @Test
  void testMonitoringReloadSuccess() {
    final CredentialBundles bundles = this.applicationContext.getBean(CredentialBundles.class);

    final CredentialMonitorHealthIndicator healthIndicator =
        this.applicationContext.getBean("credential-monitor", CredentialMonitorHealthIndicator.class);
    assertNotNull(healthIndicator);

    // Install a test function for the credential that fails once ...
    //
    final AbstractReloadablePkiCredential credential = (AbstractReloadablePkiCredential) bundles.getCredential("test1");
    credential.setTestFunction(new FailTestFunction(new SecurityException("TEST-ERROR"), 1));

    // We can't wait for the scheduled test. Invoked test manually ...
    final CredentialMonitorBean monitorBean = this.applicationContext.getBean(CredentialMonitorBean.class);
    assertNotNull(monitorBean);
    monitorBean.test();

    final Health h = healthIndicator.health();
    assertEquals(CredentialMonitorHealthIndicator.WARNING, healthIndicator.health().getStatus());
  }

  @DisplayName("Tests that monitoring and health endpoint handles reload failures")
  @Test
  void testMonitoringReloadFailed() {
    final CredentialBundles bundles = this.applicationContext.getBean(CredentialBundles.class);

    final CredentialMonitorHealthIndicator healthIndicator =
        this.applicationContext.getBean("credential-monitor", CredentialMonitorHealthIndicator.class);
    assertNotNull(healthIndicator);

    // Install a test function for the credential that fails once ...
    //
    final AbstractReloadablePkiCredential credential = (AbstractReloadablePkiCredential) bundles.getCredential("test1");
    credential.setTestFunction(new FailTestFunction(new SecurityException("TEST-ERROR"), 2));

    // We can't wait for the scheduled test. Invoked test manually ...
    final CredentialMonitorBean monitorBean = this.applicationContext.getBean(CredentialMonitorBean.class);
    assertNotNull(monitorBean);
    monitorBean.test();

    final Health h = healthIndicator.health();
    assertEquals(Status.DOWN, healthIndicator.health().getStatus());
  }

  private static class FailTestFunction implements Function<ReloadablePkiCredential, Exception> {

    private final Exception exception;
    private final int failTimes;
    private int failed = 0;

    public FailTestFunction(final Exception exception, final int failTimes) {
      this.exception = exception;
      this.failTimes = failTimes;
    }

    @Override
    public Exception apply(final ReloadablePkiCredential reloadablePkiCredential) {
      if (this.failTimes > this.failed) {
        this.failed++;
        return this.exception;
      }
      else {
        return null;
      }
    }
  }

}
