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
package se.swedenconnect.security.credential;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;

import org.springframework.core.io.Resource;

import lombok.Setter;
import se.swedenconnect.security.credential.factory.KeyStoreFactoryBean;
import se.swedenconnect.security.credential.pkcs11conf.Pkcs11Configuration;
import se.swedenconnect.security.credential.pkcs11conf.Pkcs11ConfigurationException;
import se.swedenconnect.security.credential.pkcs11conf.Pkcs11ObjectProvider;

/**
 * A mocked {@link Pkcs11Configuration} that doesn't use a PKCS#11 device but a KeyStore on disk instead.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class MockPkcs11Configuration implements Pkcs11Configuration {

  /** The KeyStore holding the private key (and certificate). */
  private KeyStore keyStore;

  /** Setting for simulating that there is no certificate available. */
  @Setter
  private boolean simulateNoCertificate = false;
  
  /** Setting for simulating that there is no private available. */
  @Setter
  private boolean simulateNoPrivateKey = false;

  /**
   * Constructor.
   * 
   * @param keyStore
   *          the keystore to pick the credential from.
   */
  public MockPkcs11Configuration(final KeyStore keyStore) {
    this.keyStore = keyStore;
  }

  /**
   * Constructor.
   * 
   * @param resource
   *          the keystore resource
   * @param password
   *          the password for unlocking the keystore
   * @throws Exception
   *           for errors loading the keystore
   */
  public MockPkcs11Configuration(final Resource resource, final char[] password) throws Exception {
    KeyStoreFactoryBean factory = new KeyStoreFactoryBean(resource, password);
    factory.afterPropertiesSet();
    this.keyStore = factory.getObject();
  }

  /** {@inheritDoc} */
  @Override
  public Provider getProvider() throws Pkcs11ConfigurationException {
    return this.keyStore.getProvider();
  }

  /** {@inheritDoc} */
  @Override
  public Pkcs11ObjectProvider<PrivateKey> getPrivateKeyProvider() {
    return (provider, alias, pin) -> {
      try {
        if (this.simulateNoPrivateKey) {
          return null;
        }
        return (PrivateKey) this.keyStore.getKey(alias, pin);
      }
      catch (Exception e) {
        throw new SecurityException(
          String.format("Failed to load private key from provider '%s' - {}", provider.getName(), e.getMessage()), e);
      }
    };
  }

  /** {@inheritDoc} */
  @Override
  public Pkcs11ObjectProvider<PkiCredential> getCredentialProvider() {
    return (provider, alias, pin) -> {
      try {
        PrivateKey pk = !this.simulateNoPrivateKey ? (PrivateKey) this.keyStore.getKey(alias, pin) : null;
        X509Certificate cert = !this.simulateNoCertificate ? (X509Certificate) this.keyStore.getCertificate(alias) : null; 
        if (pk == null && cert == null) {
          return null;
        }
        return new BasicCredential(cert, pk);
      }
      catch (Exception e) {
        throw new SecurityException(
          String.format("Failed to load private key and certificate from provider '%s' - {}", provider.getName(), e.getMessage()), e);
      }
    };
  }

}
