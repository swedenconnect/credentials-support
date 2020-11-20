/*
 * Copyright 2020 Sweden Connect
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
package se.swedenconnect.security.credential.pkcs11.configuration;

import org.junit.Assert;
import org.junit.Test;

/**
 * Test cases for SoftHsmBootstraper.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class SoftHsmBootstraperTest {

  /** Default PKCS#11 library for SoftHSM. */
  public static final String DEFAULT_SOFTHSM_PKCS11_LIB = "/usr/lib/softhsm/libsofthsm2.so";

  /** Default PKCS#11 slot to use. */
  public static final int DEFAULT_SLOT = 0;

  private static String INFO_RESPONSE_TEMPLATE = "Cryptoki version 2.40\n"
      + "Manufacturer     %s\n"
      +"Library          Implementation of PKCS11 (ver 2.4)\n"
      + "Using slot 0 with a present token (0x0)";

  @Test
  public void testIsSoftHsm() throws Exception {

    final SoftHsmBootstraper bootstrapper = new SoftHsmBootstraper();
    bootstrapper.setCommandExecutor((cmd) -> {
      if (cmd.contains("--module " + DEFAULT_SOFTHSM_PKCS11_LIB)) {
        return String.format(INFO_RESPONSE_TEMPLATE, "SoftHSM");
      }
      else {
        return String.format(INFO_RESPONSE_TEMPLATE, "Acme Inc");
      }
    });
    
    Pkcs11Configuration cfg = new DefaultPkcs11Configuration(DEFAULT_SOFTHSM_PKCS11_LIB, "SoftHsm", "0", null);
    Assert.assertTrue(bootstrapper.isSoftHsm(cfg));
    
    cfg = new DefaultPkcs11Configuration("/other/library.so", "FooBar", "0", null);
    Assert.assertFalse(bootstrapper.isSoftHsm(cfg));
  }

}
