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
package se.swedenconnect.security.credential.factory;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.Provider;
import java.security.Security;

import org.cryptacular.io.ClassPathResource;
import org.junit.jupiter.api.AfterAll;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;

import lombok.Setter;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.ReloadablePkiCredential;
import se.swedenconnect.security.credential.pkcs11.MockSunPkcs11Provider;

/**
 * Tests that credentials can be initiated using a Spring context file.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
//@ExtendWith(SpringExtension.class)
//@ContextConfiguration(locations = {"/test-config.xml"})
public class SpringTest {

  @Setter
  @Autowired(required = false)
  @Qualifier("credential1")
  private PkiCredential credential1;

  @Setter
  @Autowired(required = false)
  @Qualifier("credential2")
  private PkiCredential credential2;

  @Setter
  @Autowired(required = false)
  @Qualifier("credential2b")
  private PkiCredential credential2b;

  @Setter
  @Autowired(required = false)
  @Qualifier("credential3")
  private ReloadablePkiCredential credential3;

  @Setter
  @Autowired(required = false)
  @Qualifier("credential4")
  private ReloadablePkiCredential credential4;

  public SpringTest() {
    // Add our mocked PKCS#11 security provider.
    Security.addProvider(new MockSunPkcs11Provider());

    // We let rsa1.jks simulate our PKCS#11 device.
    MockSunPkcs11Provider.MockedPkcs11ResourceHolder.getInstance().setResource(new ClassPathResource("rsa1.jks"));
  }

  @AfterAll
  public static void afterClass() {
    Security.removeProvider(MockSunPkcs11Provider.PROVIDER_BASE_NAME);

    Provider[] providers = Security.getProviders();
    for (Provider p : providers) {
      if (p.getName().contains(MockSunPkcs11Provider.PROVIDER_BASE_NAME)) {
        Security.removeProvider(p.getName());
      }
    }
  }
/*
  @Test
  public void testBeans() throws Exception {
    assertNotNull(this.credential1, "credential1 not created");
    assertNotNull(this.credential1.getCertificate());
    assertNotNull(this.credential1.getPrivateKey());
    assertNotNull(this.credential2, "credential2 not created");
    assertNotNull(this.credential2.getCertificate());
    assertNotNull(this.credential2.getPrivateKey());
    assertNotNull(this.credential2, "credential2b not created");
    assertNotNull(this.credential2b.getCertificate());
    assertNotNull(this.credential2b.getPrivateKey());
    assertNotNull(this.credential3, "credential3 not created");
    assertNotNull(this.credential3.getCertificate());
    assertNotNull(this.credential3.getPrivateKey());
    assertNotNull(this.credential4, "credential4 not created");
    assertNotNull(this.credential4.getCertificate());
    assertNotNull(this.credential4.getPrivateKey());
  }
*/
  /*
  @Test
  public void testMonitorAndReload() throws Exception {
    // First simulate that credential 4 has stopped working ...
    //
    // Mess up the private key
    Field pk = AbstractPkiCredential.class.getDeclaredField("privateKey");
    pk.setAccessible(true);
    pk.set(this.credential4, null);

    // Wait for the monitor to detect and fix the credential ...
    //
    Thread.sleep(3000);

    // Now, it should be reloaded...
    assertNotNull(this.credential4.getPrivateKey());

  }


   */
}
