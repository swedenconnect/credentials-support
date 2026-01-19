/*
 * Copyright 2020-2026 Sweden Connect
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

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

/**
 * A default credential test function that tests a credential by getting a private key reference and signs or decrypts
 * test data using this key.
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

  /** Cache for usage of a credential. */
  private final Map<String, String> usageCache = new HashMap<>();

  /** {@inheritDoc} */
  @Override
  public Exception apply(final ReloadablePkiCredential credential) {
    try {
      if (credential.getPrivateKey() == null) {
        return new KeyException(String.format("No private key available for credential '%s'", credential.getName()));
      }

      // Check whether to test using signature or raw decryption ...
      final String usage = this.determineTestUsage(credential);
      if (PkiCredential.Metadata.USAGE_SIGNING.equals(usage)) {
        this.testSign(credential);
      }
      else if (PkiCredential.Metadata.USAGE_ENCRYPTION.equals(usage)) {
        this.testDecrypt(credential);
      }
      else {
        // We don't know. First test signing, and if we get a CKR_KEY_TYPE_INCONSISTENT error, try decryption.
        try {
          this.testSign(credential);
          this.usageCache.put(credential.getName(), PkiCredential.Metadata.USAGE_SIGNING);
        }
        catch (final Exception err) {
          if (err.getMessage().contains("CKR_KEY_TYPE_INCONSISTENT")) {
            this.usageCache.put(credential.getName(), PkiCredential.Metadata.USAGE_ENCRYPTION);
            this.testDecrypt(credential);
          }
          else {
            throw err;
          }
        }
      }
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
   * Finds out whether to test using a signature or raw decryption.
   *
   * @param credential the credential
   * @return the usage or {@code null} if it cannot be determined
   */
  private String determineTestUsage(final ReloadablePkiCredential credential) {
    final String usage = credential.getMetadata().getUsage();
    if (PkiCredential.Metadata.USAGE_SIGNING.equals(usage)
        || PkiCredential.Metadata.USAGE_METADATA_SIGNING.equals(usage)) {
      return PkiCredential.Metadata.USAGE_SIGNING;
    }
    else if (PkiCredential.Metadata.USAGE_ENCRYPTION.equals(usage)) {
      return PkiCredential.Metadata.USAGE_ENCRYPTION;
    }

    return this.usageCache.get(credential.getName());
  }

  private void testSign(final ReloadablePkiCredential credential) throws Exception {
    final PrivateKey pk = credential.getPrivateKey();
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
      throw new NoSuchAlgorithmException(msg);
    }

    final Signature signature = this.provider != null
        ? Signature.getInstance(algorithm, this.provider)
        : Signature.getInstance(algorithm);
    signature.initSign(pk);
    signature.update(TEST_DATA);
    signature.sign();
  }

  /**
   * Tests raw decryption of an RSA key.
   * <p>
   * Note: The SunPKCS11 crypto provider does not support OAEPPadding.
   * </p>
   *
   * @param credential the credential
   * @throws Exception for errors
   */
  private void testDecrypt(final ReloadablePkiCredential credential) throws Exception {
    final PrivateKey privateKey = credential.getPrivateKey();
    if (!"RSA".equals(privateKey.getAlgorithm())) {
      log.debug("Test of credential '{}' not performed - No support for decryption for key algorithm {}",
          credential.getName(), privateKey.getAlgorithm());
      return;
    }

    final RSAPublicKey pub = (RSAPublicKey) credential.getPublicKey();
    final BigInteger n = pub.getModulus();
    final BigInteger e = pub.getPublicExponent();
    final int k = (n.bitLength() + 7) / 8; // modulus length in bytes

    final SecureRandom rnd = new SecureRandom();

    // 1) pick random m in [1, n-1]
    BigInteger m;
    do {
      m = new BigInteger(n.bitLength(), rnd);
    } while (m.signum() <= 0 || m.compareTo(n) >= 0);

    // 2) c = m^e mod n
    final BigInteger c = m.modPow(e, n);

    // 3) decrypt with NoPadding
    final Cipher raw = this.provider != null
        ? Cipher.getInstance("RSA/ECB/NoPadding", this.provider)
        : Cipher.getInstance("RSA/ECB/NoPadding");

    raw.init(Cipher.DECRYPT_MODE, privateKey);

    final byte[] cBytes = toFixedLen(c, k);
    final byte[] mRecoveredBytes = raw.doFinal(cBytes);

    final BigInteger mRecovered = new BigInteger(1, mRecoveredBytes);

    // 4) compare
    if (!m.equals(mRecovered)) {
      throw new SecurityException("RSA raw decrypt test failed");
    }
  }

  private static byte[] toFixedLen(final BigInteger x, final int k) {
    final byte[] b = x.toByteArray();  // May be k+1 with leading 0x00.
    if (b.length == k) {
      return b;
    }
    final byte[] out = new byte[k];
    if (b.length > k) {
      System.arraycopy(b, b.length - k, out, 0, k);
    }
    else {
      System.arraycopy(b, 0, out, k - b.length, b.length);
    }
    return out;
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
