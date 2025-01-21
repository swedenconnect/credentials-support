/*
 * Copyright 2020-2025 Sweden Connect
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
import org.cryptacular.io.Resource;
import se.swedenconnect.security.credential.factory.KeyStoreFactory;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.Provider;

/**
 * A mocked {@link Pkcs11Configuration} that doesn't use a PKCS#11 device but a KeyStore on disk instead.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class MockPkcs11Configuration implements Pkcs11Configuration {

  /** The KeyStore holding the private key (and certificate). */
  private final KeyStore keyStore;

  /**
   * Constructor.
   *
   * @param keyStore the keystore to pick the credential from.
   */
  public MockPkcs11Configuration(final KeyStore keyStore) {
    this.keyStore = keyStore;
  }

  /**
   * Constructor.
   *
   * @param resource the keystore resource
   * @param password the password for unlocking the keystore
   * @throws Exception for errors loading the keystore
   */
  public MockPkcs11Configuration(final Resource resource, final char[] password) throws Exception {
    try (final InputStream inputStream = resource.getInputStream()) {
      this.keyStore = KeyStoreFactory.loadKeyStore(inputStream, password, null, null);
    }
  }

  /** {@inheritDoc} */
  @Nonnull
  @Override
  public Provider getProvider() throws Pkcs11ConfigurationException {
    return this.keyStore.getProvider();
  }

}
