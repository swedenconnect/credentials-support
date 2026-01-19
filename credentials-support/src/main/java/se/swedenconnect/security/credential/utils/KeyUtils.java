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
package se.swedenconnect.security.credential.utils;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.cryptacular.EncodingException;
import org.cryptacular.util.KeyPairUtil;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Utility methods for handling public and private keys.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class KeyUtils {

  /**
   * When configuring the use of credentials and when a key is configured, normally, the location of the key file is
   * given. But we also allow to give the key "inline", i.e., to enter its PEM-encoding. This method can be used to find
   * out whether a location string holds an inlined PEM-encoded key.
   *
   * @param location location configuration setting
   * @return {@code true} if the given string holds a PEM-encoding and {@code false} otherwise
   */
  public static boolean isInlinedPem(@Nonnull final String location) {
    return X509Utils.isInlinedPem(location);
  }

  /**
   * Decodes a public key in DER or PEM format.
   *
   * @param bytes the key bytes
   * @return the decoded public key
   * @throws KeyException for decoding errors
   */
  @Nonnull
  public static PublicKey decodePublicKey(@Nonnull final byte[] bytes) throws KeyException {
    try {
      return KeyPairUtil.decodePublicKey(bytes);
    }
    catch (final Exception e) {
      throw new KeyException(e.getMessage(), e);
    }
  }

  /**
   * Decodes a public key in DER or PEM format.
   * <p>
   * The method does not close the input stream.
   * </p>
   *
   * @param stream the input stream
   * @return the decoded public key
   * @throws KeyException for decoding errors
   */
  @Nonnull
  public static PublicKey decodePublicKey(@Nonnull final InputStream stream) throws KeyException {
    try {
      return decodePublicKey(stream.readAllBytes());
    }
    catch (final IOException e) {
      throw new KeyException("IO error", e);
    }
  }

  /**
   * Decodes a private key in DER, PEM, and unencrypted PKCS#8 formats.
   *
   * @param bytes the key bytes
   * @return the decoded private key
   * @throws KeyException for decoding errors
   */
  @Nonnull
  public static PrivateKey decodePrivateKey(@Nonnull final byte[] bytes) throws KeyException {
    try {
      return KeyPairUtil.decodePrivateKey(bytes);
    }
    catch (final Exception e) {
      throw new KeyException(e.getMessage(), e);
    }
  }

  /**
   * Decodes an encrypted private key. DER or PEM-encoded PKCS#8 and "OpenSSL" PEM formats are supported.
   *
   * @param bytes the key bytes
   * @param password the password, if {@code null}, the {@link #decodePrivateKey(byte[])} is called
   * @return the decoded and decrypted private key
   * @throws KeyException for decoding and decryption errors
   */
  @Nonnull
  public static PrivateKey decodePrivateKey(@Nonnull final byte[] bytes, @Nullable final char[] password)
      throws KeyException {

    if (password == null) {
      return decodePrivateKey(bytes);
    }
    try {
      return KeyPairUtil.decodePrivateKey(bytes, password);
    }
    catch (final Exception e) {
      throw new KeyException(e.getMessage(), e);
    }
  }

  /**
   * Decodes a private key in DER, PEM, and unencrypted PKCS#8 formats.
   * <p>
   * The method does not close the input stream.
   * </p>
   *
   * @param stream the input stream
   * @return the decoded private key
   * @throws KeyException for decoding errors
   */
  @Nonnull
  public static PrivateKey decodePrivateKey(@Nonnull final InputStream stream) throws KeyException {
    try {
      return decodePrivateKey(stream.readAllBytes());
    }
    catch (final IOException e) {
      throw new KeyException("IO error", e);
    }
  }

  /**
   * Decodes an encrypted private key. DER or PEM-encoded PKCS#8 and "OpenSSL" PEM formats are supported.
   * <p>
   * The method does not close the input stream.
   * </p>
   *
   * @param stream the input stream
   * @param password the password, if {@code null}, the {@link #decodePrivateKey(InputStream)} is called.
   * @return the decoded and decrypted private key
   * @throws KeyException for decoding and decryption errors
   */
  @Nonnull
  public static PrivateKey decodePrivateKey(@Nonnull final InputStream stream, @Nullable final char[] password)
      throws KeyException {
    try {
      return decodePrivateKey(stream.readAllBytes(), password);
    }
    catch (final IOException e) {
      throw new KeyException("IO error", e);
    }
  }

  // Hidden
  private KeyUtils() {
  }

}
