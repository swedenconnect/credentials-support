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
package se.swedenconnect.security.pkcs11.configuration;

import java.io.BufferedReader;
import java.io.InputStreamReader;

import lombok.extern.slf4j.Slf4j;

/**
 * If a SoftHSM device is to be used this can be configured using a {@link Pkcs11Configuration} instance. However, in
 * many cases the SoftHSM device itself needs to be bootstrapped where keys and certificates are copied to the SoftHSM.
 * This class assists in setting up a SoftHSM instance.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class SoftHsmConfigurer {

  /** The PKCS#11 configuration. */
  private Pkcs11Configuration pkcs11Configuration;

  /**
   * Constructor.
   * 
   * @param pkcs11Configuration
   *          the PKCS#11 configuration
   */
  public SoftHsmConfigurer(final Pkcs11Configuration pkcs11Configuration) {
    this.pkcs11Configuration = pkcs11Configuration;
  }

  /**
   * Checks if SoftHSM has been initialized.
   * 
   * @return true if SoftHSM already has been initialized, and false otherwise
   */
  public boolean isSoftHsmInitialized() {
    /*
     * Test command: pkcs11-tool --module {lib} --list-slots
     * 
     * Example for slot==0:
     * Response for not initialized: Slot 0 (0x0): SoftHSM slot ID 0x0 token state: uninitialized
     * Response for initialized: Available slots: Slot 0 (0x5e498485): SoftHSM slot ID 0x5e498485 token label : softhsm
     */
    final StringBuilder b = new StringBuilder();
    b.append("pkcs11-tool --module ").append(this.pkcs11Configuration.getLibrary()).append(" --list-slots");
    final String console = executeCommand(b.toString());
    
    if (console.contains("CKR_SLOT_ID_INVALID")) {
      // TODO
    }
    
    boolean uninitialized = console.indexOf("Slot 0 (0x0)") > -1 && console.indexOf("token state:   uninitialized") > -1;
    log.info("Initialized state of PKCS11 SoftHSM: {}", uninitialized ? "uninitialized" : "initialized");
    return !uninitialized;
  }

  /**
   * Execute a command line command on the host.
   *
   * @param command
   *          the command to execute
   * @return the response from the host
   */
  private static String executeCommand(final String command) {

    log.info("Executing command: {}", command);

    try {
      final Process p = Runtime.getRuntime().exec(command);
      p.waitFor();
      final BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));

      final StringBuffer output = new StringBuffer();
      String line = "";
      while ((line = reader.readLine()) != null) {
        output.append(line + "\n");
      }
      log.info("Command output: {}", output.toString());
      return output.toString();
    }
    catch (Exception e) {
      log.error("Failed to execute command: {}", e.getMessage(), e);
      return "";
    }
  }
}
