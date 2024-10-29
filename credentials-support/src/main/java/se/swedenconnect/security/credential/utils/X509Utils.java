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
package se.swedenconnect.security.credential.utils;

import org.cryptacular.EncodingException;
import org.cryptacular.StreamException;
import org.cryptacular.util.CertUtil;

import javax.security.auth.x500.X500Principal;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Utility methods for working with X.509 certificates.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class X509Utils {

  /**
   * Decodes a {@link X509Certificate} from its encoding.
   *
   * @param encoding the certificate encoding (PEM or DER encoded)
   * @return a X509Certificate object
   * @throws CertificateException for decoding errors
   */
  public static X509Certificate decodeCertificate(final byte[] encoding) throws CertificateException {
    try {
      return CertUtil.decodeCertificate(encoding);
    }
    catch (final EncodingException e) {
      throw new CertificateException("Failed to decode certificate", e);
    }
  }

  /**
   * Decodes a {@link X509Certificate} from an input stream.
   * <p>
   * The method does not close the input stream.
   * </p>
   *
   * @param stream the stream to read (holding a PEM or DER encoded certificate)
   * @return a X509Certificate object
   * @throws CertificateException for decoding errors
   */
  public static X509Certificate decodeCertificate(final InputStream stream) throws CertificateException {
    try {
      return CertUtil.readCertificate(stream);
    }
    catch (final EncodingException | StreamException e) {
      throw new CertificateException("Failed to decode certificate", e);
    }
  }

  /**
   * Given a sequence of PEM or DER encododed certificates or a PKCS#7 certificate chain, the method will return a list
   * of {@link X509Certificate} objects.
   *
   * @param encoding the sequence of PEM or DER encoded certificates or a PKCS#7 certificate chain
   * @return a list of {@link X509Certificate} objects
   * @throws CertificateException for decoding errors
   */
  public static List<X509Certificate> decodeCertificateChain(final byte[] encoding) throws CertificateException {
    try {
      return Arrays.asList(CertUtil.decodeCertificateChain(encoding));
    }
    catch (final EncodingException e) {
      throw new CertificateException("Failed to decode certificate chain", e);
    }
  }

  /**
   * Given a stream holding a sequence of PEM or DER encododed certificates or a PKCS#7 certificate chain, the method
   * will return a list of {@link X509Certificate} objects.
   * <p>
   * The method does not close the input stream.
   * </p>
   *
   * @param stream the stream
   * @return a list of {@link X509Certificate} objects
   * @throws CertificateException for decoding errors
   */
  public static List<X509Certificate> decodeCertificateChain(final InputStream stream) throws CertificateException {
    try {
      return Arrays.asList(CertUtil.readCertificateChain(stream));
    }
    catch (final EncodingException | StreamException e) {
      throw new CertificateException("Failed to decode certificate chain", e);
    }
  }

  /**
   * The {@link X509Certificate#toString()} prints way too much for a normal log entry. This method displays the
   * subject, issuer and serial number.
   *
   * @param certificate the certificate to log
   * @return a log string
   */
  public static String toLogString(final X509Certificate certificate) {
    if (certificate == null) {
      return "null";
    }
    return "subject='%s', issuer='%s', serial-number='%s'".formatted(
        Optional.ofNullable(certificate.getSubjectX500Principal())
            .map(X500Principal::getName)
            .orElse("?"),
        Optional.ofNullable(certificate.getIssuerX500Principal())
            .map(X500Principal::getName)
            .orElse("?"),
        Optional.ofNullable(certificate.getSerialNumber())
            .map(BigInteger::toString)
            .orElse("?"));
  }

  // Hidden
  private X509Utils() {
  }

}
