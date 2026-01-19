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

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.io.File;
import java.util.Objects;

/**
 * A {@link Pkcs11Configuration} where a PKCS#11 configuration file is supplied.
 * <p>
 * Note: This implementation assumes that the SunPKCS11 security provider is used, or other security providers that
 * supports the {@link java.security.KeyStoreSpi}. See {@link AbstractSunPkcs11Configuration}.
 * </p>
 * <p>
 * See <a href="https://docs.oracle.com/en/java/javase/21/security/pkcs11-reference-guide1.html">PKCS#11 Reference
 * Guide</a>.
 * </p>
 *
 * @author Martin Lindström
 */
public class FilePkcs11Configuration extends AbstractSunPkcs11Configuration {

  /** The complete path to the configuration file. */
  private final String configurationFile;

  /**
   * Constructor assigning the external PKCS#11 configuration file.
   *
   * @param configurationFile complete path to the PKCS#11 configuration file
   */
  public FilePkcs11Configuration(@Nonnull final String configurationFile) {
    this(configurationFile, null);
  }

  /**
   * Constructor assigning the external PKCS#11 configuration file and a "base provider name".
   * <p>
   * The {@code baseProviderName} is the name of the security provider that we use to create new instances that have
   * names according to {@code <base-provider-name>-<instance-name>}, where 'instance-name' is gotten from the
   * configuration. Implementations wishing to use another provider than "SunPKCS11" should supply this provider name.
   * </p>
   *
   * @param configurationFile complete path to the PKCS#11 configuration file
   * @param baseProviderName base provider name
   */
  public FilePkcs11Configuration(@Nonnull final String configurationFile, @Nullable final String baseProviderName) {
    super(baseProviderName);
    this.configurationFile = validateConfigurationFile(
        Objects.requireNonNull(configurationFile, "configurationFile must not be null"));
  }

  /**
   * Returns the configuration file.
   */
  @Override
  @Nonnull
  protected String getConfigurationData() {
    return this.configurationFile;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return "%s, config-file='%s'".formatted(super.toString(), this.configurationFile);
  }

  /**
   * Validates that the supplied configuration file exists.
   *
   * @param configurationFile the file to check
   * @return the absolute path of the file
   * @throws IllegalArgumentException if the file does not exist
   */
  private static String validateConfigurationFile(@Nonnull final String configurationFile)
      throws IllegalArgumentException {
    final File file = new File(configurationFile);
    if (!file.exists()) {
      throw new IllegalArgumentException("%s does not exist".formatted(configurationFile));
    }
    if (!file.isFile()) {
      throw new IllegalArgumentException("%s is not a file".formatted(configurationFile));
    }
    return file.getAbsolutePath();
  }

}
