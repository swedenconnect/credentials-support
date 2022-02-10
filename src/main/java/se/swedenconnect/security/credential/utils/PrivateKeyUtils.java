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
package se.swedenconnect.security.credential.utils;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyException;
import java.security.PrivateKey;

import org.cryptacular.util.KeyPairUtil;
import org.springframework.core.io.Resource;

/**
 * Utility methods for handling private keys.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class PrivateKeyUtils {

  /**
   * Decodes a private key in DER, PEM, and unencrypted PKCS#8 formats.
   * 
   * @param bytes
   *          the key bytes
   * @return the decoded private key
   * @throws KeyException
   *           for decoding errors
   */
  public static PrivateKey decodePrivateKey(final byte[] bytes) throws KeyException {
    return KeyPairUtil.decodePrivateKey(bytes);
  }

  /**
   * Decodes a private key in DER, PEM, and unencrypted PKCS#8 formats.
   * <p>
   * The method does not close the input stream.
   * </p>
   * 
   * @param stream
   *          the input stream
   * @return the decoded private key
   * @throws KeyException
   *           for decoding errors
   */
  public static PrivateKey decodePrivateKey(final InputStream stream) throws KeyException {
    try {
      return decodePrivateKey(stream.readAllBytes());
    }
    catch (final IOException e) {
      throw new KeyException("IO error", e);
    }
  }

  /**
   * Decodes a private key in DER, PEM, and unencrypted PKCS#8 formats.
   * 
   * @param resource
   *          the resource
   * @return the decoded private key
   * @throws KeyException
   *           for decoding errors
   */
  public static PrivateKey decodePrivateKey(final Resource resource) throws KeyException {
    try (final InputStream is = resource.getInputStream()) {
      return decodePrivateKey(is);
    }
    catch (final IOException e) {
      throw new KeyException("IO error", e);
    }
  }

  // Hidden
  private PrivateKeyUtils() {
  }

}
