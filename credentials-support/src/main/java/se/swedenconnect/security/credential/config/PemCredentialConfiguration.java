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
package se.swedenconnect.security.credential.config;

import java.util.Optional;

/**
 * Configuration interface for creating a {@link se.swedenconnect.security.credential.PkiCredential PkiCredential} using
 * PEM-encoded certificate(s) and private keys.
 *
 * @author Martin Lindström
 */
public interface PemCredentialConfiguration extends BaseCredentialConfiguration {

  /**
   * Location or content of the certificate or certificate chain in PEM format.
   * <p>
   * If more than one certificate is supplied, the entity certificate, i.e., the certificate holding the public key of
   * the key pair, must be placed first.
   * </p>
   *
   * @return the location or content of the certificate or certificate chain in PEM format
   */
  String certificates();

  /**
   * Location or content of the private key in PEM format.
   *
   * @return the location or content of the private key in PEM format
   */
  String privateKey();

  /**
   * Password used to decrypt an encrypted private key.
   *
   * @return key password
   */
  Optional<String> keyPassword();

}
