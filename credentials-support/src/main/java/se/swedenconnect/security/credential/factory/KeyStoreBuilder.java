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
package se.swedenconnect.security.credential.factory;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.swedenconnect.security.credential.config.ConfigurationResourceLoader;
import se.swedenconnect.security.credential.config.DefaultConfigurationResourceLoader;
import se.swedenconnect.security.credential.pkcs11.CustomPkcs11Configuration;
import se.swedenconnect.security.credential.pkcs11.FilePkcs11Configuration;
import se.swedenconnect.security.credential.pkcs11.Pkcs11Configuration;
import se.swedenconnect.security.credential.pkcs11.StaticPkcs11Configuration;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.util.Objects;
import java.util.Optional;

/**
 * A class implementing a builder pattern for setting up a {@link KeyStore}.
 *
 * @author Martin Lindström
 */
public class KeyStoreBuilder {

  /** The resource loader. */
  private final ConfigurationResourceLoader resourceLoader;

  /** The KeyStore type. */
  private String type = KeyStore.getDefaultType();

  /** The location for the key store. */
  private String location;

  /** The key store password. */
  private String password;

  /** The name of the security provider. */
  private String provider;

  /** The path to the PKCS#11 configuration file. */
  private String pkcs11ConfigurationFile;

  /** The PKCS#11 library path. */
  private String pkcs11Library;

  /** The name of the HSM slot. */
  private String pkcs11SlotName;

  /** The HSM slot number/id to use. */
  private String pkcs11Slot;

  /** The HSM slot index to use. */
  private Integer pkcs11SlotListIndex;

  /**
   * Default constructor.
   * <p>
   * Will use the {@link DefaultConfigurationResourceLoader} to load resources.
   * </p>
   */
  public KeyStoreBuilder() {
    this(null);
  }

  /**
   * Constructor assigning the resource loader to use when loading resources.
   *
   * @param resourceLoader the resource loader, if {@code null}, a {@link DefaultConfigurationResourceLoader} will
   *     be used
   */
  public KeyStoreBuilder(@Nullable final ConfigurationResourceLoader resourceLoader) {
    this.resourceLoader = Optional.ofNullable(resourceLoader)
        .orElseGet(DefaultConfigurationResourceLoader::new);
  }

  /**
   * Creates a {@link KeyStoreBuilder} that uses the {@link DefaultConfigurationResourceLoader} to load resources.
   *
   * @return a {@link KeyStoreBuilder}
   */
  @Nonnull
  public static KeyStoreBuilder builder() {
    return new KeyStoreBuilder();
  }

  /**
   * Creates a {@link KeyStoreBuilder} that uses the supplied {@link ConfigurationResourceLoader} to load resources.
   *
   * @param resourceLoader the resource loader
   * @return a {@link KeyStoreBuilder}
   */
  @Nonnull
  public static KeyStoreBuilder builder(@Nullable final ConfigurationResourceLoader resourceLoader) {
    return new KeyStoreBuilder(resourceLoader);
  }

  /**
   * Given the properties assigned, the method loads and unlocks a {@link KeyStore}.
   *
   * @return the {@link KeyStore}
   * @throws IllegalArgumentException for missing or incorrect indata
   * @throws IOException if the supplied location can not be read
   * @throws KeyStoreException for errors during loading and unlocking of the key store (for example, bad password)
   * @throws NoSuchProviderException if the given provider is not available
   */
  @Nonnull
  public KeyStore build() throws IllegalArgumentException, IOException, KeyStoreException, NoSuchProviderException {
    if (this.password == null) {
      throw new IllegalArgumentException("Missing password/pin");
    }

    if (this.type.equalsIgnoreCase("PKCS11")) {
      final Pkcs11Configuration pkcs11Configuration;
      if (this.pkcs11ConfigurationFile != null) {
        pkcs11Configuration = new FilePkcs11Configuration(this.pkcs11ConfigurationFile, this.provider);
      }
      else if (this.pkcs11Library != null && this.pkcs11SlotName != null) {
        pkcs11Configuration = new CustomPkcs11Configuration(this.pkcs11Library, this.pkcs11SlotName,
            this.pkcs11Slot, this.pkcs11SlotListIndex, this.provider);
      }
      else {
        pkcs11Configuration = new StaticPkcs11Configuration(this.provider);
      }
      return KeyStoreFactory.loadPkcs11KeyStore(pkcs11Configuration, this.password.toCharArray());
    }
    else {
      if (this.location == null) {
        throw new IllegalArgumentException("Missing location");
      }
      try (final InputStream stream = this.resourceLoader.getStream(this.location)) {
        return KeyStoreFactory.loadKeyStore(stream, this.password.toCharArray(), this.type, this.provider);
      }
    }
  }

  /**
   * Assigns the {@link KeyStore} type. If not assigned, {@link KeyStore#getDefaultType()} will be assumed.
   *
   * @param type the key store type
   * @return the builder
   */
  @Nonnull
  public KeyStoreBuilder type(@Nonnull final String type) {
    this.type = Objects.requireNonNull(type, "type must not be null");
    return this;
  }

  /**
   * Assigns the location for the {@link KeyStore}. Will be read by the installed {@link ConfigurationResourceLoader}.
   * <p>
   * Note: No location should be assigned for PKCS#11 key stores.
   * </p>
   *
   * @param location the location
   * @return the builder
   */
  @Nonnull
  public KeyStoreBuilder location(@Nonnull final String location) {
    this.location = Objects.requireNonNull(location, "location must not be null");
    return this;
  }

  /**
   * Assigns the key store password.
   *
   * @param password the password
   * @return the builder
   */
  @Nonnull
  public KeyStoreBuilder password(@Nonnull final String password) {
    this.password = Objects.requireNonNull(password, "password must not be null");
    return this;
  }

  /**
   * Assigns the PIN, which is the same as the key store password. When using PKCS#11 devices, the concept PIN is
   * commoncly used instead of password.
   *
   * @param pin the PIN
   * @return the builder
   */
  @Nonnull
  public KeyStoreBuilder pin(@Nonnull final String pin) {
    this.password = Objects.requireNonNull(pin, "pin must not be null");
    return this;
  }

  /**
   * Assigns the name of the security {@link java.security.Provider Provider} to use. If not assigned, the default
   * provider will be used.
   *
   * @param provider the name of the security provider to use
   * @return the builder
   */
  @Nonnull
  public KeyStoreBuilder provider(@Nonnull final String provider) {
    this.provider = Objects.requireNonNull(provider, "provider must not be null");
    return this;
  }

  /**
   * Assigns the full path to the PKCS#11 configuration file (for PKCS#11 key stores).
   *
   * @param pkcs11ConfigurationFile the full path to the PKCS#11 configuration file
   * @return the builder
   */
  @Nonnull
  public KeyStoreBuilder pkcs11ConfigurationFile(@Nonnull final String pkcs11ConfigurationFile) {
    this.pkcs11ConfigurationFile =
        Objects.requireNonNull(pkcs11ConfigurationFile, "pkcs11ConfigurationFile must not be null");
    return this;
  }

  /**
   * As an alternative to assigning the PKCS#11 configuration file, each PKCS#11 setting may be supplied separately.
   * This method assigns the PKCS#11 library path.
   *
   * @param pkcs11Library the PKCS#11 library path
   * @return the builder
   */
  @Nonnull
  public KeyStoreBuilder pkcs11Library(@Nonnull final String pkcs11Library) {
    this.pkcs11Library = Objects.requireNonNull(pkcs11Library, "pkcs11Library must not be null");
    return this;
  }

  /**
   * As an alternative to assigning the PKCS#11 configuration file, each PKCS#11 setting may be supplied separately.
   * This method assigns the HSM slot name to use.
   *
   * @param pkcs11SlotName the HSM slot name
   * @return the builder
   */
  @Nonnull
  public KeyStoreBuilder pkcs11SlotName(@Nonnull final String pkcs11SlotName) {
    this.pkcs11SlotName = Objects.requireNonNull(pkcs11SlotName, "pkcs11SlotName must not be null");
    return this;
  }

  /**
   * As an alternative to assigning the PKCS#11 configuration file, each PKCS#11 setting may be supplied separately.
   * This method assigns the HSM slot number/id to use.
   *
   * @param pkcs11Slot the HSM slot number/id
   * @return the builder
   */
  @Nonnull
  public KeyStoreBuilder pkcs11Slot(@Nonnull final String pkcs11Slot) {
    this.pkcs11Slot = Objects.requireNonNull(pkcs11Slot, "pkcs11Slot must not be null");
    return this;
  }

  /**
   * As an alternative to assigning the PKCS#11 configuration file, each PKCS#11 setting may be supplied separately.
   * This method assigned the HSM slot index to use.
   *
   * @param pkcs11SlotListIndex the HSM slot index
   * @return the builder
   */
  @Nonnull
  public KeyStoreBuilder pkcs11SlotListIndex(@Nonnull final Integer pkcs11SlotListIndex) {
    this.pkcs11SlotListIndex = Objects.requireNonNull(pkcs11SlotListIndex, "pkcs11SlotListIndex must not be null");
    return this;
  }

}
