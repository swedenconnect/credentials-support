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
package se.swedenconnect.security.credential.test;

import org.opensaml.security.x509.X509Credential;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import se.swedenconnect.security.credential.PkiCredential;

import javax.crypto.Cipher;
import java.security.Signature;
import java.util.Arrays;

/**
 * Service responsible for testing the credentials.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Service
public class TestCredentialsService {

  /** The bytes that we sign ... */
  private static final byte[] TEST_BYTES = "TestStringToSign".getBytes();

  private final PkiCredential rsa1;
  private final PkiCredential rsa1b;
  private final PkiCredential rsa2;
  public final X509Credential openSamlRsa1;

  public TestCredentialsService(final @Qualifier("rsa1") PkiCredential rsa1,
      final @Qualifier("rsa1b") PkiCredential rsa1b,
      final @Qualifier("rsa2") PkiCredential rsa2,
      final @Qualifier("rsa1_OpenSaml") X509Credential openSamlRsa1) {
    this.rsa1 = rsa1;
    this.rsa1b = rsa1b;
    this.rsa2 = rsa2;
    this.openSamlRsa1 = openSamlRsa1;
  }

  public String test() {
    return this.testSignAndVerify(this.rsa1) + System.lineSeparator() + System.lineSeparator()
        + this.testSignAndVerify(this.rsa1b) + System.lineSeparator() + System.lineSeparator()
        + this.testSignAndVerify(this.rsa2) + System.lineSeparator();
  }

  private String testSignAndVerify(final PkiCredential credential) {
    final StringBuilder sb = new StringBuilder();
    sb.append("Testing credential ").append(credential.getName()).append(System.lineSeparator());

    try {
      sb.append("  Signing using SHA256withRSA...").append(System.lineSeparator());
      Signature signature = Signature.getInstance("SHA256withRSA");
      signature.initSign(credential.getPrivateKey());
      signature.update(TEST_BYTES);
      final byte[] signatureBytes = signature.sign();
      sb.append("    Success").append(System.lineSeparator());

      sb.append("  Verifying signature...").append(System.lineSeparator());
      signature = Signature.getInstance("SHA256withRSA");
      signature.initVerify(credential.getPublicKey());
      signature.update(TEST_BYTES);
      final boolean r = signature.verify(signatureBytes);
      if (r) {
        sb.append("    Success").append(System.lineSeparator());
      }
      else {
        sb.append("    Error: Signature did not verify correctly").append(System.lineSeparator());
      }

      sb.append("  Encrypting using RSA/ECB/PKCS1Padding...").append(System.lineSeparator());
      Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      cipher.init(Cipher.ENCRYPT_MODE, credential.getPublicKey());
      final byte[] encryptedbytes = cipher.doFinal(TEST_BYTES);
      sb.append("    Success").append(System.lineSeparator());

      sb.append("  Decrypting data...").append(System.lineSeparator());
      cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      cipher.init(Cipher.DECRYPT_MODE, credential.getPrivateKey());
      final byte[] decryptedBytes = cipher.doFinal(encryptedbytes);
      if (Arrays.equals(TEST_BYTES, decryptedBytes)) {
        sb.append("    Success").append(System.lineSeparator());
      }
      else {
        sb.append("    Error: Decrypted data does not correspond to original data").append(System.lineSeparator());
      }
    }
    catch (final Exception e) {
      sb.append("    Error: ").append(e.getClass().getSimpleName()).append(" - ").append(e.getMessage())
          .append(System.lineSeparator());
    }

    return sb.toString();
  }

}
