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
import org.springframework.core.io.Resource;
import se.swedenconnect.security.credential.PkiCredential;

import java.util.List;

/**
 * A utility factory that can create any type of {@link PkiCredential}.
 * <p>
 * This implementation will be removed in future releases. Consider using {@link PkiCredentialFactory} or
 * {@link se.swedenconnect.security.credential.spring.factory.PkiCredentialFactoryBean} instead.
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 * @deprecated Use {@link PkiCredentialFactory} or
 *     {@link se.swedenconnect.security.credential.spring.factory.PkiCredentialFactoryBean} instead.
 */
@Deprecated(since = "2.0.0", forRemoval = true)
public class PkiCredentialFactoryBean
    extends se.swedenconnect.security.credential.spring.factory.PkiCredentialFactoryBean {

  /**
   * Default constructor.
   */
  public PkiCredentialFactoryBean() {
    super(new PkiCredentialConfigurationProperties());
  }

  /**
   * Constructor that initializes the factory from the supplied credential configuration properties object.
   *
   * @param properties credential configuration properties
   */
  public PkiCredentialFactoryBean(@Nonnull final PkiCredentialConfigurationProperties properties) {
    super(properties);
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected PkiCredential createInstance() throws Exception {
    this.getUnderlyingProperties().afterPropertiesSet();
    return super.createInstance();
  }

  /**
   * Assigns the name of the credential.
   *
   * @param name the credential name
   */
  public void setName(final String name) {
    this.getUnderlyingProperties().setName(name);
  }

  /**
   * Assigns the resource holding the certificate part of the credential (optional since the certificate may be part of
   * a keystore).
   *
   * @param certificate certificate resource
   */
  public void setCertificate(final Resource certificate) {
    this.getUnderlyingProperties().setCertificate(certificate);
  }

  /**
   * Assigns the list of resources holding the certificate chain that part of the credential (optional since the
   * certificate may be part of a keystore). If used, the entity certificate must be the first element.
   *
   * @param certificates a list of certificate resources
   */
  public void setCertificates(final List<Resource> certificates) {
    this.getUnderlyingProperties().setCertificates(certificates);
  }

  /**
   * Assigns the resource holding the private key part of the credential (optional since the key may be part of a
   * keystore).
   *
   * @param privateKey private key resource
   */
  public void setPrivateKey(final Resource privateKey) {
    this.getUnderlyingProperties().setPrivateKey(privateKey);
  }

  /**
   * Assigns the resource to the keystore containing the credential.
   *
   * @param resource the keystore resource
   */
  public void setResource(final Resource resource) {
    this.getUnderlyingProperties().setResource(resource);
  }

  /**
   * Assigns the keystore password.
   *
   * @param password keystore password
   */
  public void setPassword(final char[] password) {
    this.getUnderlyingProperties().setPassword(password);
  }

  /**
   * Assigns the type of keystore.
   *
   * @param type the keystore type
   */
  public void setType(final String type) {
    this.getUnderlyingProperties().setType(type);
  }

  /**
   * Assigns the name of the security provider to use when creating the KeyStore instance.
   *
   * @param provider security provider name
   */
  public void setProvider(final String provider) {
    this.getUnderlyingProperties().setProvider(provider);
  }

  /**
   * Assigns the PKCS#11 configuration file to use.
   *
   * @param pkcs11Configuration PKCS#11 configuration file (full path)
   */
  public void setPkcs11Configuration(final String pkcs11Configuration) {
    this.getUnderlyingProperties().setPkcs11Configuration(pkcs11Configuration);
  }

  /**
   * Assigns the keystore alias to the entry holding the key pair.
   *
   * @param alias keystore alias
   */
  public void setAlias(final String alias) {
    this.getUnderlyingProperties().setAlias(alias);
  }

  /**
   * Assigns the password to unlock the private key from the keystore.
   *
   * @param keyPassword the key password
   */
  public void setKeyPassword(final char[] keyPassword) {
    this.getUnderlyingProperties().setKeyPassword(keyPassword);
  }

  /**
   * Assigns the PIN. The same as keyPassword (used mainly for PKCS#11 credentials).
   *
   * @param pin the PIN
   */
  public void setPin(final char[] pin) {
    this.setKeyPassword(pin);
  }

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() throws Exception {
    this.getUnderlyingProperties().afterPropertiesSet();
    super.afterPropertiesSet();
  }

  private PkiCredentialConfigurationProperties getUnderlyingProperties() {
    return (PkiCredentialConfigurationProperties) this.getConfiguration();
  }

}
