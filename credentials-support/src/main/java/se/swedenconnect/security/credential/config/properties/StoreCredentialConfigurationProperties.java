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

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.security.credential.config.StoreConfiguration;
import se.swedenconnect.security.credential.config.StoreCredentialConfiguration;

import java.util.Objects;
import java.util.Optional;

/**
 * Configuration properties for creating a {@link se.swedenconnect.security.credential.PkiCredential PkiCredential}
 * backed by a Java {@link java.security.KeyStore KeyStore}.
 *
 * @author Martin Lindström
 */
public class StoreCredentialConfigurationProperties extends AbstractBaseCredentialConfigurationProperties
    implements StoreCredentialConfiguration {

  /**
   * Configuration for the KeyStore holding the key pair entry. Mutually exclusive with the store-reference property.
   */
  @Getter
  @Setter
  @org.springframework.boot.context.properties.NestedConfigurationProperty
  private StoreConfigurationProperties store;

  /**
   * A store reference. As an alternative to giving the key store configuration, a reference to a key store
   * configuration may be given. This feature may be used when one key store holds several keys.
   */
  @Getter
  @Setter
  private String storeReference;

  /**
   * Whether the credential should be prepared for monitoring. If set, a test function and a KeyStoreReloader will be
   * assigned.
   */
  @Getter
  @Setter
  private Boolean monitor;

  /**
   * Configuration for the key pair entry of the store.
   */
  @Getter
  @Setter
  private KeyConfigurationProperties key;

  /** {@inheritDoc} */
  @Override
  public Optional<StoreConfiguration> store() {
    return Optional.ofNullable(this.getStore());
  }

  /** {@inheritDoc} */
  @Override
  public Optional<String> storeReference() {
    return Optional.ofNullable(this.getStoreReference());
  }

  /** {@inheritDoc} */
  @Override
  public Optional<Boolean> monitor() {
    return Optional.ofNullable(this.getMonitor());
  }

  /** {@inheritDoc} */
  @Override
  public KeyConfiguration key() {
    return this.getKey();
  }

  /**
   * Configuration properties for a key pair entry.
   */
  public static class KeyConfigurationProperties implements KeyConfiguration {

    /**
     * The alias that identifies the key pair in the key store.
     */
    @Getter
    @Setter
    private String alias;

    /**
     * For some credentials where an underlying KeyStore is being used, an external certificate should be used. The most
     * typical example would be a PKCS#11 key store where the certificate of the key pair resides outside the HSM
     * device. This setting holds the location or content of the certificate or certificate chain in PEM format.
     */
    @Getter
    @Setter
    private String certificates;

    /**
     * The password to unlock the key entry identified by the given alias. If not given, the store password will be used
     * (in these cases, using a store reference will not function).
     */
    @Getter
    @Setter
    private String keyPassword;

    /** {@inheritDoc} */
    @Override
    public String alias() {
      return this.getAlias();
    }

    /** {@inheritDoc} */
    @Override
    public Optional<String> keyPassword() {
      return Optional.ofNullable(this.getKeyPassword());
    }

    /** {@inheritDoc} */
    @Override
    public Optional<String> certificates() {
      return Optional.ofNullable(this.getCertificates());
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
      final KeyConfigurationProperties that = (KeyConfigurationProperties) o;
      return Objects.equals(this.alias, that.alias) && Objects.equals(this.certificates, that.certificates)
          && Objects.equals(this.keyPassword, that.keyPassword);
    }

    /** {@inheritDoc} */
    @Override
    public int hashCode() {
      return Objects.hash(this.alias, this.certificates, this.keyPassword);
    }
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
    if (!super.equals(o)) {
      return false;
    }
    final StoreCredentialConfigurationProperties that = (StoreCredentialConfigurationProperties) o;
    return Objects.equals(this.store, that.store) && Objects.equals(this.storeReference, that.storeReference)
        && Objects.equals(this.monitor, that.monitor) && Objects.equals(this.key, that.key);
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hash(super.hashCode(), this.store, this.storeReference, this.monitor, this.key);
  }
}
