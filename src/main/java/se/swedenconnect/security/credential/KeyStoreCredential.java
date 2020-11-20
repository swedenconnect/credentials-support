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
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;

/**
 * A {@link KeyStore} backed implementation of the {@link KeyPairCredential} interface.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class KeyStoreCredential extends BasicCredential {

  /**
   * Constructor.
   * 
   * @param keyStore
   *          the keystore to read the key pair from
   * @param alias
   *          the alias to the entry holding the key pair
   * @param keyPassword
   *          the password to unlock the key pair
   * @throws UnrecoverableKeyException
   *           if the key cannot be recovered (e.g., the given password is wrong)
   * @throws KeyStoreException
   *           if the keystore has not been initialized (loaded)
   * @throws NoSuchAlgorithmException
   *           if the algorithm for recovering the private key could not be found
   */
  public KeyStoreCredential(final KeyStore keyStore, final String alias, final char[] keyPassword)
      throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {

    super((X509Certificate) keyStore.getCertificate(alias), (PrivateKey) keyStore.getKey(alias, keyPassword));
    this.setName(alias);
  }

}
