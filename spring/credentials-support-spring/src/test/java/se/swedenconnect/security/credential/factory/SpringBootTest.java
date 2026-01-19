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
package se.swedenconnect.security.credential.factory;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.scheduling.annotation.Scheduled;

import lombok.Setter;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.ReloadablePkiCredential;
import se.swedenconnect.security.credential.monitoring.CredentialMonitorBean;

/**
 * Tests that credentials can be initiated using Spring boot configuration properties.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
//@ExtendWith(SpringExtension.class)
//@EnableConfigurationProperties(value = CredentialsConfiguration.class)
//@TestPropertySource(locations = { "classpath:application.properties" })
//@EnableScheduling
public class SpringBootTest {

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
  @Qualifier("credential3")
  private ReloadablePkiCredential credential3;

  @Setter
  @Autowired(required = false)
  @Qualifier("credential4")
  private ReloadablePkiCredential credential4;

  @Setter
  @Autowired
  private CredentialMonitorBean credentialMonitorBean;

  @Scheduled(fixedDelay = 1000, initialDelay = 1000)
  public void scheduleCredentialMonitor() {
    this.credentialMonitorBean.test();
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
