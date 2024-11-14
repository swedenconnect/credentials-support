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
package se.swedenconnect.security.credential.config.properties;

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.security.credential.config.PemCredentialConfiguration;

import java.util.Optional;

/**
 * Configuration properties for creating a {@link se.swedenconnect.security.credential.PkiCredential PkiCredential}
 * using PEM-encoded certificate(s) and private keys.
 *
 * @author Martin Lindström
 */
public class PemCredentialConfigurationProperties extends AbstractBaseCredentialConfigurationProperties implements
    PemCredentialConfiguration {

  /**
   * Location or content of the certificate or certificate chain in PEM format. If more than one certificate is
   * supplied, the entity certificate, i.e., the certificate holding the public key of * the key pair, must be placed
   * first.
   */
  @Getter
  @Setter
  private String certificates;

  /**
   * Location or content of the private key in PEM format.
   */
  @Getter
  @Setter
  private String privateKey;

  /**
   * Password used to decrypt an encrypted private key.
   */
  @Getter
  @Setter
  private String keyPassword;

  /** {@inheritDoc} */
  @Override
  public String certificates() {
    return this.getCertificates();
  }

  /** {@inheritDoc} */
  @Override
  public String privateKey() {
    return this.getPrivateKey();
  }

  /** {@inheritDoc} */
  @Override
  public Optional<String> keyPassword() {
    return Optional.ofNullable(this.getKeyPassword());
  }

}
