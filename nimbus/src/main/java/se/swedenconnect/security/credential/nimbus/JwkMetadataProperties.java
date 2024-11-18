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
package se.swedenconnect.security.credential.nimbus;

/**
 * Symbolic constants for storing JWK properties in a
 * {@link se.swedenconnect.security.credential.PkiCredential.Metadata PkiCredential.Metadata} object.
 *
 * @author Martin Lindström
 */
public class JwkMetadataProperties {

  /**
   * Property name for the key use metadata property. Maps to JWK's {@code use} property. Should hold a {@link String}
   * or a {@link com.nimbusds.jose.jwk.KeyUse KeyUse}.
   */
  public static final String KEY_USE_PROPERTY = "key-use";

  /**
   * Property name for the key operations metadata property. Maps to JWK's {@code ops} property. Should hold a
   * {@link java.util.Set Set} of {@link String}s or {@link com.nimbusds.jose.jwk.KeyOperation KeyOperation}s, or a
   * comma-separated string.
   */
  public static final String KEY_OPS_PROPERTY = "key-ops";

  /**
   * Property name for the JOSE algorithm {@code alg} metadata property. Maps to JWK's {@code alg} property. Should hold
   * a {@link com.nimbusds.jose.Algorithm Algorithm} or a string.
   */
  public static final String JOSE_ALGORITHM_PROPERTY = "jose-alg";

  // Hidden
  private JwkMetadataProperties() {
  }
}
