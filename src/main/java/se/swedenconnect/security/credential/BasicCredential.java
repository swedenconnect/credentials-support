/*
 * Copyright 2020-2022 Sweden Connect
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
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.UUID;

import org.springframework.core.io.Resource;

/**
 * A basic implementation of the {@link PkiCredential} interface.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class BasicCredential extends AbstractPkiCredential {

  /**
   * Default constructor.
   */
  public BasicCredential() {
    super();
  }

  /**
   * Constructor setting the public and private keys.
   * 
   * @param publicKey
   *          the public key
   * @param privateKey
   *          the private key
   */
  public BasicCredential(final PublicKey publicKey, final PrivateKey privateKey) {
    this.setPublicKey(publicKey);
    this.setPrivateKey(privateKey);
  }

  /**
   * Constructor setting the certificate and private key.
   * 
   * @param certificate
   *          the certificate
   * @param privateKey
   *          the private key
   */
  public BasicCredential(final X509Certificate certificate, final PrivateKey privateKey) {
    this.setCertificate(certificate);
    this.setPrivateKey(privateKey);
  }

  /**
   * Constructor setting the certificate and private key.
   * 
   * @param certificateResource
   *          the resource holding a encoded certificate
   * @param privateKey
   *          the private key
   * @throws CertificateException
   *           if the certificate resource can not be decoded
   */
  public BasicCredential(final Resource certificateResource, final PrivateKey privateKey) throws CertificateException {
    this.setCertificate(certificateResource);
    this.setPrivateKey(privateKey);
  }
  
  /**
   * Constructor setting the certificate(s) and private key.
   * 
   * @param certificates
   *          the certificate(s) where the entity certificate is placed first
   * @param privateKey
   *          the private key
   */
  public BasicCredential(final List<X509Certificate> certificates, final PrivateKey privateKey) {
    this.setCertificateChain(certificates);
    this.setPrivateKey(privateKey);
  }  

  /**
   * Gets the subject DN of the certificate and if no certificate is available an UUID is used.
   */
  @Override
  protected String getDefaultName() {
    final X509Certificate cert = this.getCertificate();
    if (cert != null) {
      return cert.getSubjectX500Principal().getName();
    }
    final PublicKey key = this.getPublicKey();
    if (key != null) {
      return String.format("%s-%s", key.getAlgorithm(), UUID.randomUUID());
    }
    return "BasicCredential-" + UUID.randomUUID().toString();
  }
  
}
