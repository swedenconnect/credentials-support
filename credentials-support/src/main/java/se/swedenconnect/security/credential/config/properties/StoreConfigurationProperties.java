/*
 * Copyright 2020-2024 Sweden Connect
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
package se.swedenconnect.security.credential.config.properties;

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.security.credential.config.StoreConfiguration;

import java.util.Optional;

/**
 * Configuration properties for creating a Java {@link java.security.KeyStore KeyStore}.
 *
 * @author Martin Lindström
 */
public class StoreConfigurationProperties implements StoreConfiguration {

  /**
   * Location of the resource containing the store content.
   */
  @Getter
  @Setter
  private String location;

  /**
   * Password used to access the store.
   */
  @Getter
  @Setter
  private String password;

  /**
   * Type of the store to create, e.g., JKS, PKCS12 or PKCS11.
   */
  @Getter
  @Setter
  private String type;

  /**
   * Security provider for the store.
   */
  @Getter
  @Setter
  private String provider;

  /**
   * If the {@code type} is "PKCS11" and a provider that is not statically configured for PKCS#11, additional PKCS#11
   * configuration needs to be supplied. Note that the security provider used must support PKCS#11 via the KeyStoreSpi
   * interface. The "SunPKCS11" is such a provider.
   */
  @Getter
  @Setter
  private Pkcs11ConfigurationProperties pkcs11;

  /** {@inheritDoc} */
  @Override
  public Optional<String> location() {
    return Optional.ofNullable(this.getLocation());
  }

  /** {@inheritDoc} */
  @Override
  public String password() {
    return this.getPassword();
  }

  /** {@inheritDoc} */
  @Override
  public Optional<String> type() {
    return Optional.ofNullable(this.getType());
  }

  /** {@inheritDoc} */
  @Override
  public Optional<String> provider() {
    return Optional.ofNullable(this.getProvider());
  }

  /** {@inheritDoc} */
  @Override
  public Optional<Pkcs11Configuration> pkcs11() {
    return Optional.ofNullable(this.getPkcs11());
  }

  /**
   * Additional configuration of PKCS11 keystores.
   */
  public static class Pkcs11ConfigurationProperties implements Pkcs11Configuration {

    /**
     * The complete path of the PKCS#11 configuration file with which the PKCS#11 device is configured.
     */
    @Getter
    @Setter
    private String configurationFile;

    /**
     * As an alternative to providing the PKCS#11 configuration file, each PKCS#11 setting can be provided separately.
     * This property holds these detailed settings.
     */
    @Getter
    @Setter
    private Pkcs11SettingsProperties settings;

    /** {@inheritDoc} */
    @Override
    public Optional<String> configurationFile() {
      return Optional.ofNullable(this.getConfigurationFile());
    }

    /** {@inheritDoc} */
    @Override
    public Optional<Pkcs11Settings> settings() {
      return Optional.ofNullable(this.getSettings());
    }

    /**
     * Custom PKCS#11 settings.
     */
    public static class Pkcs11SettingsProperties implements Pkcs11Configuration.Pkcs11Settings {

      /**
       * The PKCS#11 library path.
       */
      @Getter
      @Setter
      private String library;

      /**
       * The name of the PKCS#11 slot.
       */
      @Getter
      @Setter
      private String name;

      /**
       * The slot number/id to use.
       */
      @Getter
      @Setter
      private String slot;

      /**
       * The slot index to use.
       */
      @Getter
      @Setter
      private Integer slotListIndex;

      /** {@inheritDoc} */
      @Override
      public String library() {
        return this.getLibrary();
      }

      /** {@inheritDoc} */
      @Override
      public String name() {
        return this.getName();
      }

      /** {@inheritDoc} */
      @Override
      public Optional<String> slot() {
        return Optional.ofNullable(this.getSlot());
      }

      /** {@inheritDoc} */
      @Override
      public Optional<Integer> slotListIndex() {
        return Optional.ofNullable(this.getSlotListIndex());
      }
    }
  }

}
