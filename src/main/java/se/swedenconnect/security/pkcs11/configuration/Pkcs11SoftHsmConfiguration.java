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

/**
 * PKCS#11 configuration when using Soft HSM.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class Pkcs11SoftHsmConfiguration implements Pkcs11Configuration {

  public Pkcs11SoftHsmConfiguration(final Pkcs11Configuration configuration) {
  }

  /** {@index} */
  @Override
  public String getConfigurationData() {
    return null;
  }

  @Override
  public String getLibrary() {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public String getName() {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public String getSlot() {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public Integer getSlotListIndex() {
    // TODO Auto-generated method stub
    return null;
  }

}
