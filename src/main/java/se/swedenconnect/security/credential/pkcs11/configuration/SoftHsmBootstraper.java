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

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.regex.Pattern;

import lombok.Setter;
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
public class SoftHsmBootstraper {

  /** The command executor. */
  @Setter
  private CommandExecutor commandExecutor = new DefaultCommandExecutor();

  /** Pattern for checking if the device is SoftHSM. */
  private static final Pattern isSoftHsmPattern = Pattern.compile("(\\s)?Manufacturer(\\s)+SoftHSM(\\s)?", Pattern.CASE_INSENSITIVE);

  /**
   * Predicate checks if the supplied configuration is for a SoftHsm device.
   * 
   * @param pkcs11Configuration
   *          the PKCS#11 configuration
   * @return true if the supplied configuration refers to SoftHsm device and false otherwise
   */
  public boolean isSoftHsm(final Pkcs11Configuration pkcs11Configuration) {
    final String cmd = String.format("pkcs11-tool --module %s --show-info", pkcs11Configuration.getLibrary());
    final String response = this.commandExecutor.execute(cmd);
    return isSoftHsmPattern.matcher(response).find();
  }

  /**
   * Checks if SoftHSM has been initialized.
   * 
   * @param pkcs11Configuration
   *          the PKCS#11 configuration
   * @return true if SoftHSM already has been initialized, and false otherwise
   * @throws Pkcs11ConfigurationException
   *           if this is not a SoftHSM device
   */
  public boolean isSoftHsmInitialized(final Pkcs11Configuration pkcs11Configuration) throws Pkcs11ConfigurationException {
    /*
     * Test command: pkcs11-tool --module {lib} --list-slots
     * 
     * Example for slot==0: Response for not initialized: Slot 0 (0x0): SoftHSM slot ID 0x0 token state: uninitialized
     * Response for initialized: Available slots: Slot 0 (0x5e498485): SoftHSM slot ID 0x5e498485 token label : softhsm
     */
    final String cmd = String.format("pkcs11-tool --module %s --list-slots --show-info", pkcs11Configuration.getLibrary());
    final String response = this.commandExecutor.execute(cmd);
    
    // First make sure that this really is a SoftHSM device.
    if (!isSoftHsmPattern.matcher(response).find()) {
      throw new Pkcs11ConfigurationException("Not a SoftHSM device");
    }
    
    Integer slotListIndex = pkcs11Configuration.getSlotListIndex();
    
    String slot = pkcs11Configuration.getSlot();

    if (response.contains("CKR_SLOT_ID_INVALID")) {
      // TODO
    }

    boolean uninitialized = response.indexOf("Slot 0 (0x0)") > -1 && response.indexOf("token state:   uninitialized") > -1;
    log.debug("Initialized state of PKCS11 SoftHSM: {}", uninitialized ? "uninitialized" : "initialized");
    return !uninitialized;
  }

// Totaly empty:
  
//  root@58cfa02e43e3:/usr/src/luna-client# pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --list-slots --show-info
//  Cryptoki version 2.40
//  Manufacturer     SoftHSM
//  Library          Implementation of PKCS11 (ver 2.4)
//  Available slots:
//  Slot 0 (0x0): SoftHSM slot ID 0x0
//    token state:   uninitialized
//  Using slot 0 with a present token (0x0)
  
  public void initializeToken(final Pkcs11Configuration pkcs11Configuration) throws Pkcs11ConfigurationException {
    
    if (pkcs11Configuration.getSlot() == null) {
      
    }
    
    final String cmd = String.format("pkcs11-tool --module %s --init-token --slot %s", 
      pkcs11Configuration.getLibrary(), pkcs11Configuration.getSlot());
  }

  /**
   * An interface for a command executor. The reason we introduce the command executor as an interface is mainly so that
   * we can mock commands during testing.
   */
  @FunctionalInterface
  public interface CommandExecutor {

    /**
     * Execute a command line command on the host.
     *
     * @param command
     *          the command to execute
     * @return the response from the host
     */
    String execute(final String command);
  }

  /**
   * The default implementation of the command executor interface.
   */
  @Slf4j
  public static class DefaultCommandExecutor implements CommandExecutor {

    @Override
    public String execute(final String command) {
      log.debug("Executing command: {}", command);

      try {
        final Process p = Runtime.getRuntime().exec(command);
        p.waitFor();

        try (InputStream is = p.getInputStream();
            InputStreamReader isreader = new InputStreamReader(is);
            BufferedReader reader = new BufferedReader(isreader)) {

          final StringBuffer output = new StringBuffer();
          String line = "";
          while ((line = reader.readLine()) != null) {
            output.append(line + "\n");
          }
          final String response = output.toString();
          log.debug("Command output: {}", response);
          return response;
        }
      }
      catch (Exception e) {
        log.error("Failed to execute command: {}", e.getMessage(), e);
        return "ERROR - " + e.getMessage();
      }
    }

  }

}
