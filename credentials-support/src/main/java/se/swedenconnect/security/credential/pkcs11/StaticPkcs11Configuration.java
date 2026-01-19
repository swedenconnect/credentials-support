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
package se.swedenconnect.security.credential.pkcs11;

import jakarta.annotation.Nullable;

/**
 * A {@link Pkcs11Configuration} where the SunPKCS11 provider is statically configured (see below).
 * <p>
 * A SunPKCS11 provider can be statically configured in the {@code java.security} file. For example:
 * </p>
 * <pre>
 * ...
 * security.provider.13=SunPKCS11 /opt/bar/cfg/pkcs11.cfg
 * ...
 * </pre>
 * <p>
 * See <a href="https://docs.oracle.com/en/java/javase/21/security/pkcs11-reference-guide1.html">PKCS#11 Reference
 * Guide</a>.
 * </p>
 *
 * @author Martin Lindström
 */
public class StaticPkcs11Configuration extends AbstractSunPkcs11Configuration {

  /**
   * Default constructor.
   */
  public StaticPkcs11Configuration() {
    super();
  }

  /**
   * See {@link AbstractSunPkcs11Configuration#AbstractSunPkcs11Configuration(String)}.
   *
   * @param providerName the security provider name (SunPKCS11 is the default)
   */
  public StaticPkcs11Configuration(@Nullable final String providerName) {
    super(providerName);
  }

  /**
   * Returns {@code null} since this configuration represents a static configuration.
   */
  @Nullable
  @Override
  protected String getConfigurationData() {
    return null;
  }

}
