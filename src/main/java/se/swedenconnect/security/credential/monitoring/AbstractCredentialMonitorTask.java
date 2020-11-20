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
package se.swedenconnect.security.credential.monitoring;

import java.util.Arrays;
import java.util.List;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.credential.KeyPairCredential;

@Slf4j
public abstract class AbstractCredentialMonitorTask implements Runnable {
  
  private final KeyPairCredential testCredential;
  
  private final List<KeyPairCredential> reloadList;

  public AbstractCredentialMonitorTask(final KeyPairCredential testCredential) {
    this(testCredential, Arrays.asList(testCredential));
  }
  
  public AbstractCredentialMonitorTask(final KeyPairCredential testCredential, final List<KeyPairCredential> reloadList) {
    this.testCredential = testCredential;
    this.reloadList = reloadList;
  }

  /** {@inheritDoc} */
  @Override
  public void run() {
    log.trace("Testing credential '{}' ...", this.testCredential.getName());
    
    try {
      this.test(this.testCredential);
      log.trace("Test of credential '{}' was successful", this.testCredential.getName());
    }
    catch (Exception e) {
      log.error("Test of credential '{}' failed - {}", this.testCredential.getName(), e.getMessage());
      log.info("Credential failure details", e);
      
      this.reloadList.forEach((c) -> this.reload(c)); 
    }
    
  }
  
  protected void reload(final KeyPairCredential credential) {
    try {
      log.debug("Reloading credential '{}' ...", credential.getName());
      credential.reload();
      log.debug("Credential '{}' successfully reloaded", credential.getName());
    }
    catch (Exception e) {
      log.error("Reloading of credential '{}' failed - {}", this.testCredential.getName(), e.getMessage());
      log.info("Credential failure details", e);
    }
  }
  
  protected abstract void test(final KeyPairCredential credential) throws SecurityException;

}
