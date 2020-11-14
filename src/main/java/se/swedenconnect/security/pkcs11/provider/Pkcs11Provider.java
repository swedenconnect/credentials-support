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
package se.swedenconnect.security.pkcs11.provider;

import java.security.Provider;

public class Pkcs11Provider extends Provider {

  /**
   * 
   */
  private static final long serialVersionUID = -2457647470127753264L;

  public Pkcs11Provider(String name, String versionStr, String info) {
    super(name, versionStr, info);
    // TODO Auto-generated constructor stub
    
  }

}
