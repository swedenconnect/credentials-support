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
package se.swedenconnect.security.credential.config.properties;

import jakarta.annotation.Nullable;
import se.swedenconnect.security.credential.config.StoreConfiguration;

import java.util.Objects;
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
  private String location;

  /**
   * Password used to access the store.
   */
  private String password;

  /**
   * Type of the store to create, e.g., JKS, PKCS12 or PKCS11.
   */
  private String type;

  /**
   * Security provider for the store.
   */
  private String provider;

  /**
   * If the {@code type} is "PKCS11" and a provider that is not statically configured for PKCS#11, additional PKCS#11
   * configuration needs to be supplied. Note that the security provider used must support PKCS#11 via the KeyStoreSpi
   * interface. The "SunPKCS11" is such a provider.
   */
  private Pkcs11ConfigurationProperties pkcs11;

  /**
   * Gets the location of the resource containing the store content.
   *
   * @return the store location
   */
  @Nullable
  public String getLocation() {
    return this.location;
  }

  /**
   * Assigns the location of the resource containing the store content.
   *
   * @param location the store location
   */
  public void setLocation(@Nullable final String location) {
    this.location = location;
  }

  /**
   * Gets the password used to access the store.
   *
   * @return the store password
   */
  @Nullable
  public String getPassword() {
    return this.password;
  }

  /**
   * Assigns the password used to access the store.
   *
   * @param password the store password
   */
  public void setPassword(@Nullable final String password) {
    this.password = password;
  }

  /**
   * Gets the type of the store to create, e.g., JKS, PKCS12 or PKCS11.
   *
   * @return the store type
   */
  @Nullable
  public String getType() {
    return this.type;
  }

  /**
   * Assigns the type of the store to create, e.g., JKS, PKCS12 or PKCS11.
   *
   * @param type the store type
   */
  public void setType(@Nullable final String type) {
    this.type = type;
  }

  /**
   * Gets the security provider for the store.
   *
   * @return the security provider name
   */
  @Nullable
  public String getProvider() {
    return this.provider;
  }

  /**
   * Assigns the security provider for the store.
   *
   * @param provider the security provider name
   */
  public void setProvider(@Nullable final String provider) {
    this.provider = provider;
  }

  /**
   * Gets the additional PKCS#11 configuration.
   *
   * @return the PKCS#11 configuration
   */
  @Nullable
  public Pkcs11ConfigurationProperties getPkcs11() {
    return this.pkcs11;
  }

  /**
   * Assigns the additional PKCS#11 configuration.
   *
   * @param pkcs11 the PKCS#11 configuration
   */
  public void setPkcs11(@Nullable final Pkcs11ConfigurationProperties pkcs11) {
    this.pkcs11 = pkcs11;
  }

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
    private String configurationFile;

    /**
     * As an alternative to providing the PKCS#11 configuration file, each PKCS#11 setting can be provided separately.
     * This property holds these detailed settings.
     */
    private Pkcs11SettingsProperties settings;

    /**
     * Gets the complete path of the PKCS#11 configuration file.
     *
     * @return the PKCS#11 configuration file
     */
    @Nullable
    public String getConfigurationFile() {
      return this.configurationFile;
    }

    /**
     * Assigns the complete path of the PKCS#11 configuration file.
     *
     * @param configurationFile the PKCS#11 configuration file
     */
    public void setConfigurationFile(@Nullable final String configurationFile) {
      this.configurationFile = configurationFile;
    }

    /**
     * Gets the detailed PKCS#11 settings (alternative to a configuration file).
     *
     * @return the PKCS#11 settings
     */
    @Nullable
    public Pkcs11SettingsProperties getSettings() {
      return this.settings;
    }

    /**
     * Assigns the detailed PKCS#11 settings (alternative to a configuration file).
     *
     * @param settings the PKCS#11 settings
     */
    public void setSettings(@Nullable final Pkcs11SettingsProperties settings) {
      this.settings = settings;
    }

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

    /** {@inheritDoc} */
    @Override
    public boolean equals(final Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || this.getClass() != o.getClass()) {
        return false;
      }
      final Pkcs11ConfigurationProperties that = (Pkcs11ConfigurationProperties) o;
      return Objects.equals(this.configurationFile, that.configurationFile) && Objects.equals(this.settings,
          that.settings);
    }

    /** {@inheritDoc} */
    @Override
    public int hashCode() {
      return Objects.hash(this.configurationFile, this.settings);
    }

    /**
     * Custom PKCS#11 settings.
     */
    public static class Pkcs11SettingsProperties implements Pkcs11Configuration.Pkcs11Settings {

      /**
       * The PKCS#11 library path.
       */
      private String library;

      /**
       * The name of the PKCS#11 slot.
       */
      private String name;

      /**
       * The slot number/id to use.
       */
      private String slot;

      /**
       * The slot index to use.
       */
      private Integer slotListIndex;

      /**
       * Gets the PKCS#11 library path.
       *
       * @return the library path
       */
      @Nullable
      public String getLibrary() {
        return this.library;
      }

      /**
       * Assigns the PKCS#11 library path.
       *
       * @param library the library path
       */
      public void setLibrary(@Nullable final String library) {
        this.library = library;
      }

      /**
       * Gets the name of the PKCS#11 slot.
       *
       * @return the slot name
       */
      @Nullable
      public String getName() {
        return this.name;
      }

      /**
       * Assigns the name of the PKCS#11 slot.
       *
       * @param name the slot name
       */
      public void setName(@Nullable final String name) {
        this.name = name;
      }

      /**
       * Gets the slot number/id to use.
       *
       * @return the slot number/id
       */
      @Nullable
      public String getSlot() {
        return this.slot;
      }

      /**
       * Assigns the slot number/id to use.
       *
       * @param slot the slot number/id
       */
      public void setSlot(@Nullable final String slot) {
        this.slot = slot;
      }

      /**
       * Gets the slot index to use.
       *
       * @return the slot index
       */
      @Nullable
      public Integer getSlotListIndex() {
        return this.slotListIndex;
      }

      /**
       * Assigns the slot index to use.
       *
       * @param slotListIndex the slot index
       */
      public void setSlotListIndex(@Nullable final Integer slotListIndex) {
        this.slotListIndex = slotListIndex;
      }

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

      /** {@inheritDoc} */
      @Override
      public boolean equals(final Object o) {
        if (this == o) {
          return true;
        }
        if (o == null || this.getClass() != o.getClass()) {
          return false;
        }
        final Pkcs11SettingsProperties that = (Pkcs11SettingsProperties) o;
        return Objects.equals(this.library, that.library) && Objects.equals(this.name, that.name)
            && Objects.equals(this.slot, that.slot) && Objects.equals(this.slotListIndex, that.slotListIndex);
      }

      /** {@inheritDoc} */
      @Override
      public int hashCode() {
        return Objects.hash(this.library, this.name, this.slot, this.slotListIndex);
      }

    }
  }

}
