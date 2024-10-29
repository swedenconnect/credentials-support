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
package se.swedenconnect.security.credential.pkcs11;

import jakarta.annotation.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

import javax.annotation.Nonnull;
import java.security.Provider;
import java.security.Security;

/**
 * Test cases for {@link CustomPkcs11Configuration}.
 *
 * @author Martin Lindström
 */
public class CustomPkcs11ConfigurationTest {

  private static final String LIBRARY = "/opt/foo/lib/libpkcs11.so";
  private static final String NAME = "mocked";

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
    final TestCustomPkcs11Configuration conf = new TestCustomPkcs11Configuration(LIBRARY, NAME, null, null);
    conf.init();
    Assertions.assertEquals("--library = %s%sname = %s%s"
        .formatted(LIBRARY, System.lineSeparator(), NAME, System.lineSeparator()), conf.getConfigurationData());

    final TestCustomPkcs11Configuration conf2 = new TestCustomPkcs11Configuration(LIBRARY, NAME, "SLOT", null);
    conf.init();
    Assertions.assertEquals("--library = %s%sname = %s%sslot = SLOT%s"
            .formatted(LIBRARY, System.lineSeparator(), NAME, System.lineSeparator(), System.lineSeparator()),
        conf2.getConfigurationData());

    final TestCustomPkcs11Configuration conf3 = new TestCustomPkcs11Configuration(LIBRARY, NAME, "SLOT", 7);
    conf.init();
    Assertions.assertEquals("--library = %s%sname = %s%sslot = SLOT%sslotListIndex = 7%s"
            .formatted(LIBRARY, System.lineSeparator(), NAME, System.lineSeparator(), System.lineSeparator(),
                System.lineSeparator()),
        conf3.getConfigurationData());
  }

  @Test
  void testBadIndex() {
    final String msg = Assertions.assertThrows(IllegalArgumentException.class,
        () -> new TestCustomPkcs11Configuration(LIBRARY, NAME, "SLOT", -7)).getMessage();
    Assertions.assertEquals("slotListIndex must be 0 or greater", msg);
  }

  @Test
  void testBadLibraryAndName() {
    final String msg = Assertions.assertThrows(IllegalArgumentException.class,
        () -> new TestCustomPkcs11Configuration(" ", NAME, "SLOT", 7)).getMessage();
    Assertions.assertEquals("library must be assigned", msg);

    final String msg2 = Assertions.assertThrows(IllegalArgumentException.class,
        () -> new TestCustomPkcs11Configuration(LIBRARY, "  ", "SLOT", 7)).getMessage();
    Assertions.assertEquals("name must be assigned", msg2);
  }

  // TODO: toString

  private static class TestCustomPkcs11Configuration extends CustomPkcs11Configuration {

    public TestCustomPkcs11Configuration(@Nonnull final String library, @Nonnull final String name,
        @Nullable final String slot, @Nullable final Integer slotListIndex) {
      super(library, name, slot, slotListIndex);
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
