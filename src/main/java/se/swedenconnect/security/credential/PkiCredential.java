/*
 * Copyright 2020-2024 Sweden Connect
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

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;

import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;

/**
 * A representation of a PKI key pair that holds a private key and a X.509 certificate (or just a public key).
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface PkiCredential extends InitializingBean, DisposableBean {

  /**
   * Gets the public key.
   *
   * @return the public key
   */
  PublicKey getPublicKey();

  /**
   * Gets the certificate holding the public key of the key pair. May be null depending on whether certificates are
   * handled by the implementing class.
   *
   * @return the certificate, or null if no certificate is configured for the credential
   */
  X509Certificate getCertificate();

  /**
   * Assigns a certificate to an already created credential holding only a key pair. It is the caller's responsibility
   * to ensure that the certificate matches the present private key.
   *
   * @param certificate the certificate to add
   */
  void setCertificate(final X509Certificate certificate);

  /**
   * Gets a certificate chain for the credential, where the first element is the entity certificate
   * ({@link #getCertificate()}). If no certificate is configured for the credential an empty list is returned.
   *
   * @return a list of certificates, or an empty list
   */
  List<X509Certificate> getCertificateChain();

  /**
   * Assigns a certificate chain to an already created credential holding only a key pair. The entity certificate is
   * placed first in the list. It is the caller's responsibility to ensure that the certificate matches the present
   * private key.
   *
   * @param certificates the chain
   */
  void setCertificateChain(final List<X509Certificate> certificates);

  /**
   * Gets the private key.
   *
   * @return the private key
   */
  PrivateKey getPrivateKey();

  /**
   * Gets the name of the credential.
   *
   * @return the name
   */
  String getName();

  /**
   * Predicate that tells whether this credential resides in a hardware module.
   *
   * @return {@code true} if the credential resides in a hardware module and {@code false} otherwise
   */
  default boolean isHardwareCredential() {
    return false;
  }

  /**
   * The {@code init} method is here just because it is a nicer name for {@code afterPropertiesSet}. Should be manually
   * invoked if the instance is not instantiated as a Spring bean.
   *
   * @throws Exception for init errors
   */
  default void init() throws Exception {
    this.afterPropertiesSet();
  }

}
