/*
 * Copyright 2020-2021 Sweden Connect
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

import java.security.Signature;
import java.util.Arrays;

import javax.crypto.Cipher;

import org.opensaml.security.x509.X509Credential;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import lombok.Setter;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * Service responsible of testing the credentials.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Service
public class TestCredentialsService {

  /** The bytes that we sign ... */
  private static final byte[] TEST_BYTES = "TestStringToSign".getBytes();

  @Setter
  @Autowired
  @Qualifier("rsa1")
  private PkiCredential rsa1;

  @Setter
  @Autowired
  @Qualifier("rsa1b")
  private PkiCredential rsa1b;

  @Setter
  @Autowired
  @Qualifier("rsa1bb")
  private PkiCredential rsa1bb;

  @Setter
  @Autowired
  @Qualifier("rsa1_OpenSaml")
  public X509Credential openSamlRsa1;
  
  public String test() {
    StringBuffer sb = new StringBuffer();
    sb.append(this.testSignAndVerify(this.rsa1)).append(System.lineSeparator()).append(System.lineSeparator());
    sb.append(this.testSignAndVerify(this.rsa1b)).append(System.lineSeparator()).append(System.lineSeparator());
    sb.append(this.testSignAndVerify(this.rsa1bb)).append(System.lineSeparator());
    return sb.toString();
  }

  private String testSignAndVerify(final PkiCredential credential) {
    final StringBuffer sb = new StringBuffer();
    sb.append("Testing credential ").append(credential.getName()).append(System.lineSeparator());
    
    try {
      sb.append("  Signing using SHA256withRSA...").append(System.lineSeparator());    
      Signature signature = Signature.getInstance("SHA256withRSA");
      signature.initSign(credential.getPrivateKey());
      signature.update(TEST_BYTES);
      byte[] signatureBytes = signature.sign();
      sb.append("    Success").append(System.lineSeparator());

      sb.append("  Verifying signature...").append(System.lineSeparator());
      signature = Signature.getInstance("SHA256withRSA");
      signature.initVerify(credential.getPublicKey());
      signature.update(TEST_BYTES);
      boolean r = signature.verify(signatureBytes);
      if (r) {
        sb.append("    Success").append(System.lineSeparator());
      }
      else {
        sb.append("    Error: Signature did not verify correctly").append(System.lineSeparator());
      }
      
      sb.append("  Encrypting using RSA/ECB/PKCS1Padding...").append(System.lineSeparator());
      Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      cipher.init(Cipher.ENCRYPT_MODE, credential.getPublicKey());
      byte[] encryptedbytes = cipher.doFinal(TEST_BYTES);
      sb.append("    Success").append(System.lineSeparator());
      
      sb.append("  Decrypting data...").append(System.lineSeparator());
      cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      cipher.init(Cipher.DECRYPT_MODE, credential.getPrivateKey());
      byte[] decryptedBytes = cipher.doFinal(encryptedbytes);
      if (Arrays.equals(TEST_BYTES, decryptedBytes)) {
        sb.append("    Success").append(System.lineSeparator());
      }
      else {
        sb.append("    Error: Decrypted data does not correspond to original data").append(System.lineSeparator());
      }
    }
    catch (Exception e) {
      sb.append("    Error: ").append(e.getClass().getSimpleName()).append(" - ").append(e.getMessage()).append(System.lineSeparator());
    }

    return sb.toString();
  }

}
