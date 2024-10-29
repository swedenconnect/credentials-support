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
package se.swedenconnect.security.credential.monitoring;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.ReloadablePkiCredential;

import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.util.Optional;
import java.util.function.Function;

/**
 * A default credential test function that tests a credential by getting a private key reference and signs test data
 * using this key. The following key algorithms are supported:
 * <ul>
 * <li><b>RSA</b> - {@code SHA256withRSA} is the default algorithm when signing.</li>
 * <li><b>DSA</b> - {@code SHA256withDSA} is the default algorithm when signing.</li>
 * <li><b>EC</b> - {@code SHA256withECDSA} is the default algorithm when signing.</li>
 * </ul>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class DefaultCredentialTestFunction implements Function<ReloadablePkiCredential, Exception> {

  /** The name of the security provider to use. May be {@code null}. */
  private String provider;

  /** The RSA signature algorithm to use. Defaults to SHA256withRSA. */
  private String rsaSignatureAlgorithm = "SHA256withRSA";

  /** The DSA signature algorithm to use. Defaults to SHA256withDSA. */
  private String dsaSignatureAlgorithm = "SHA256withDSA";

  /** The EC signature algorithm to use. Defaults to SHA256withECDSA. */
  private String ecSignatureAlgorithm = "SHA256withECDSA";

  /** The data that is signed. */
  private static final byte[] TEST_DATA = "testdata".getBytes();

  /** {@inheritDoc} */
  @Override
  public Exception apply(final ReloadablePkiCredential credential) {
    try {
      final PrivateKey pk = credential.getPrivateKey();
      if (pk == null) {
        return new KeyException(String.format("No private key available for credential '%s'", credential.getName()));
      }

      final String algorithm;
      if ("RSA".equals(pk.getAlgorithm())) {
        algorithm = this.rsaSignatureAlgorithm;
      }
      else if ("DSA".equals(pk.getAlgorithm())) {
        algorithm = this.dsaSignatureAlgorithm;
      }
      else if ("EC".equals(pk.getAlgorithm())) {
        algorithm = this.ecSignatureAlgorithm;
      }
      else {
        final String msg = String.format("Unknown private key algorithm (%s) - Cannot perform test of credential '%s'",
            pk.getAlgorithm(), credential.getName());
        log.warn("{}", msg);
        return new NoSuchAlgorithmException(msg);
      }
      final Signature signature =
          this.provider != null ? Signature.getInstance(algorithm, this.provider) : Signature.getInstance(algorithm);
      signature.initSign(pk);
      signature.update(TEST_DATA);
      signature.sign();
    }
    catch (final Exception e) {
      log.debug("Test of credential '{}' failed - {}",
          Optional.ofNullable(credential).map(PkiCredential::getName).orElse("null"), e.getMessage());
      return e;
    }

    log.trace("Test of credential '{}' was successful", credential.getName());
    return null;
  }

  /**
   * The name for a specific security {@link Provider} to use.
   *
   * @param provider provider name
   */
  public void setProvider(final String provider) {
    this.provider = provider;
  }

  /**
   * Assigns the RSA signature algorithm to use. Defaults to SHA256withRSA.
   *
   * @param rsaSignatureAlgorithm the JCA algorithm name
   */
  public void setRsaSignatureAlgorithm(final String rsaSignatureAlgorithm) {
    if (rsaSignatureAlgorithm != null) {
      this.rsaSignatureAlgorithm = rsaSignatureAlgorithm;
    }
  }

  /**
   * Assigns the DSA signature algorithm to use. Defaults to SHA256withDSA.
   *
   * @param dsaSignatureAlgorithm the JCA algorithm name
   */
  public void setDsaSignatureAlgorithm(final String dsaSignatureAlgorithm) {
    if (dsaSignatureAlgorithm != null) {
      this.dsaSignatureAlgorithm = dsaSignatureAlgorithm;
    }
  }

  /**
   * Assigns the EC signature algorithm to use. Defaults to SHA256withECDSA.
   *
   * @param ecSignatureAlgorithm the JCA algorithm name
   */
  public void setEcSignatureAlgorithm(final String ecSignatureAlgorithm) {
    if (ecSignatureAlgorithm != null) {
      this.ecSignatureAlgorithm = ecSignatureAlgorithm;
    }
  }

}
