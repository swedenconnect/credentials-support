/*
 * Copyright 2020 IDsec Solutions AB
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
package se.swedenconnect.security.pkcs11.credential;

import java.security.KeyStore;
import java.security.cert.X509Certificate;

import lombok.extern.slf4j.Slf4j;

/**
 * Representation of a PKCS#11 credential. The class uses a PKCS#11 {@link KeyStore} and is basically a wrapper for
 * getting the private key (and entity certificate).
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class Pkcs11Credential {

  /**
   * If the entity certificate is not available from the underlying KeyStore it may be assigned directly. If set, no
   * access to the keystore will be performed to obtain the certificate ({@link #setCertificate(X509Certificate)}).
   */
  private X509Certificate certificate;

  private final String alias;

  private KeyStore keyStore;

  public Pkcs11Credential(final String alias) {
    this.alias = alias;
  }

  /**
   * Gets the entity certificate. If the certificate was assigned (using {@link #setCertificate(X509Certificate)}) this
   * will be returned, otherwise an attempt to get it from the underlying KeyStore will be made.
   * 
   * @return the entity certificate, or null if none is found
   */
  public X509Certificate getCertificate() {
    if (this.certificate != null) {
      return this.certificate;
    }
    else {
      // TODO
      return null;
    }
  }

  /**
   * If the entity certificate isn't stored on the device behind the PKCS#11 interface, or if direct access to the
   * entity certificate without querying the device is required, it may be assigned to the object.
   * 
   * @param certificate
   *          the entity certificate
   */
  public void setCertificate(final X509Certificate certificate) {
    this.certificate = certificate;
  }

}
