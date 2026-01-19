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
import jakarta.annotation.PreDestroy;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.credential.AbstractReloadablePkiCredential;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.ReloadablePkiCredential;
import se.swedenconnect.security.credential.monitoring.DefaultCredentialTestFunction;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * A PKCS#11 credential implementation of the {@link PkiCredential} and {@link ReloadablePkiCredential} interfaces.
 * <p>
 * Note: In all cases where the SunPKCS11 security provider is used, it is recommended to use the
 * {@link KeyStoreCredential} implementation instead.
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class Pkcs11Credential extends AbstractReloadablePkiCredential {

  /** The PKCS#11 configuration for the token that holds this credential. */
  private final Pkcs11Configuration configuration;

  /** The private key accessor. */
  private final Pkcs11PrivateKeyAccessor privateKeyAccessor;

  /** The certificates accessor. */
  private final Pkcs11CertificatesAccessor certificatesAccessor;

  /** The alias of the key pair on the token. */
  private final String alias;

  /** The PIN (key password) needed to unlock the token. */
  private final char[] pin;

  /** The cached private key. */
  private PrivateKey privateKey;

  /** Certificates for the credential - cache. */
  private final List<X509Certificate> certificates;

  /**
   * Constructor.
   *
   * @param configuration the PKCS#11 configuration
   * @param alias the token entry from where to load the private key and certificate
   * @param pin the PIN to unlock the token
   * @param privateKeyAccessor the {@link Pkcs11PrivateKeyAccessor}
   * @param certificatesAccessor the {@link Pkcs11CertificatesAccessor}
   * @throws Pkcs11ConfigurationException for configuration errors
   */
  public Pkcs11Credential(@Nonnull final Pkcs11Configuration configuration, @Nonnull final String alias,
      @Nonnull final char[] pin, @Nonnull final Pkcs11PrivateKeyAccessor privateKeyAccessor,
      @Nonnull final Pkcs11CertificatesAccessor certificatesAccessor) throws Pkcs11ConfigurationException {

    this.configuration = Objects.requireNonNull(configuration, "configuration must not be null");
    this.alias = Objects.requireNonNull(alias, "alias must not be null");
    this.pin = new char[Objects.requireNonNull(pin, "pin must not be null").length];
    System.arraycopy(pin, 0, this.pin, 0, pin.length);

    this.privateKeyAccessor = Objects.requireNonNull(privateKeyAccessor, "privateKeyAccessor must not be null");
    this.certificatesAccessor = Objects.requireNonNull(certificatesAccessor, "certificatesAccessor must not be null");

    final Provider provider = configuration.getProvider();

    this.privateKey = this.privateKeyAccessor.get(provider, this.alias, this.pin);
    this.certificates = Optional.ofNullable(this.certificatesAccessor.get(provider, this.alias, this.pin))
        .filter(c -> c.length > 0)
        .map(Arrays::asList)
        .orElseThrow(() -> new Pkcs11ConfigurationException("No certificates available"));

    // Install a default test function - this may be overridden by setTestFunction later ...
    final DefaultCredentialTestFunction testFunction = new DefaultCredentialTestFunction();
    testFunction.setProvider(provider.getName());
    this.setTestFunction(testFunction);

    // Finally, update metadata properties with settings for issued-at and expires-at ...
    //
    this.updateMetadataValidityProperties();
  }

  /**
   * Constructor that takes a list of X.509 certificates as an argument instead of a {@link Pkcs11CertificatesAccessor}.
   * This constructor should be used if we know that the certificate chain is not placed on the device (only the private
   * key).
   *
   * @param configuration the PKCS#11 configuration
   * @param alias the token entry from where to load the private key and certificate
   * @param pin the PIN to unlock the token
   * @param privateKeyAccessor the {@link Pkcs11PrivateKeyAccessor}
   * @param certificates the certificate chain (entity certificate placed first)
   * @throws Pkcs11ConfigurationException for configuration errors
   */
  public Pkcs11Credential(@Nonnull final Pkcs11Configuration configuration, @Nonnull final String alias,
      @Nonnull final char[] pin, @Nonnull final Pkcs11PrivateKeyAccessor privateKeyAccessor,
      @Nonnull final List<X509Certificate> certificates) throws Pkcs11ConfigurationException {

    this(configuration, alias, pin, privateKeyAccessor, new StaticCertificateAccessor(certificates));
  }

  /** {@inheritDoc} */
  @Nonnull
  @Override
  public PrivateKey getPrivateKey() {
    return this.privateKey;
  }

  /** {@inheritDoc} */
  @Nonnull
  @Override
  public List<X509Certificate> getCertificateChain() {
    return this.certificates;
  }

  /**
   * Returns {@code true}.
   */
  @Override
  public boolean isHardwareCredential() {
    return true;
  }

  /**
   * Is called if the connection to the device has been lost. In those cases we reload the private key.
   */
  @Override
  public void reload() throws Exception {

    // Note: We log only on trace level since the monitor driving the reloading is responsible
    // for the actual logging.
    //
    final Provider provider = this.configuration.getProvider();
    log.trace("Reloading private key under alias '{}' for provider '{}' ...", this.alias, provider.getName());
    this.privateKey = this.privateKeyAccessor.get(provider, this.alias, this.pin);

    log.trace("Private key under alias '{}' for provider '{}' was reloaded", this.alias, provider.getName());
  }

  /**
   * Clears the saved PIN code.
   */
  @PreDestroy
  public void destroy() {
    if (this.pin != null) {
      Arrays.fill(this.pin, (char) 0);
    }
  }

  /** {@inheritDoc} */
  @Nonnull
  @Override
  protected String getDefaultName() {

    String providerName;
    try {
      providerName = this.configuration.getProvider().getName();
    }
    catch (final Exception e) {
      providerName = "pkcs11";
    }

    return "%s-%s".formatted(providerName, this.alias);
  }

  // Support class for handling externally provided certificates ...
  //
  private static class StaticCertificateAccessor implements Pkcs11CertificatesAccessor {

    private final X509Certificate[] chain;

    public StaticCertificateAccessor(@Nullable final List<X509Certificate> certificates) {
      this.chain = Objects.requireNonNull(certificates, "certificates must not be null")
          .toArray(new X509Certificate[0]);
      if (this.chain.length == 0) {
        throw new IllegalArgumentException("At least one certificate must be provided");
      }
    }

    @Nullable
    @Override
    public X509Certificate[] get(@Nonnull final Provider provider, @Nonnull final String alias,
        @Nonnull final char[] pin) throws SecurityException {
      return this.chain;
    }
  }

}
