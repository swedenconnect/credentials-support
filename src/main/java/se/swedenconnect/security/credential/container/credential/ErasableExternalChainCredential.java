/*
 * Copyright (c) 2021-2022. Agency for Digital Government (DIGG)
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
package se.swedenconnect.security.credential.container.credential;

import se.swedenconnect.security.credential.PkiCredential;

import java.security.KeyStore;

/**
 * Extends a  {@link ExternalChainCredential} which implements {@link PkiCredential} and provides a credential
 * that is intended to be used to be associated with a temporary key generated on an HSM device.
 *
 * <p>
 *   This implementation of PKI credential is not intended to be implemented as a bean, but is rather provided by
 *   a HSM key generation process that includes 2 separate steps:
 * </p>
 *
 * <ul>
 * <li>The credential is first created inside a hsm slot</li>
 * <li>This credential key is used to generate a first self issued certificate sotred in the HSM</li>
 * <li>The public key is sent to a CA for certification and the resulting chain is imported in to the credential but not to the HSM slot</li>
 * <li>After usage, the credential provides the necessary functions to permanently delete the key from the HSM</li>
 * </ul>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ErasableExternalChainCredential extends ExternalChainCredential {

  /** Key store used to manage the key and primary certificate of the credential */
  KeyStore keyStore;
  /** alias of the credential key and certificate in the key store */
  String alias;

  /**
   * Constructor providing an external chain credential with destructible key from a base credential.
   *
   * @param baseCredential a base credential holding a private and a public key
   */
  public ErasableExternalChainCredential(PkiCredential baseCredential, KeyStore keyStore, String alias) {
    super(baseCredential);
    this.alias = alias;
    this.keyStore = keyStore;
  }

  /** {@inheritDoc} */
  @Override
  public void destroy() throws Exception {
    this.keyStore.deleteEntry(this.alias);
  }

}
