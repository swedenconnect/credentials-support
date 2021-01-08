/*
 * Copyright 2020 Sweden Connect
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.opensaml.security.x509.X509Credential;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * Controller for the test application.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Controller
public class TestController {

  /** The bytes that we sign ... */
  private static final byte[] SIGN_BYTES = "TestStringToSign".getBytes();

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

  @GetMapping("/")
  public ModelAndView home() {
    ModelAndView mav = new ModelAndView("home");
    mav.addObject("result", Arrays.asList(this.testSignAndVerify(this.rsa1),
      this.testSignAndVerify(this.rsa1b), this.testSignAndVerify(this.rsa1bb)));
    return mav;
  }

  private Result testSignAndVerify(final PkiCredential credential) {
    final Result result = new Result("Testing credential " + credential.getName());

    try {
      result.setActionOperation("Signing using SHA256withRSA");
      Signature signature = Signature.getInstance("SHA256withRSA");
      signature.initSign(credential.getPrivateKey());
      signature.update(SIGN_BYTES);
      byte[] signatureBytes = signature.sign();
      result.setActionResult("Success");

      result.setActionOperation("Verifying signature");
      signature = Signature.getInstance("SHA256withRSA");
      signature.initVerify(credential.getPublicKey());
      signature.update(SIGN_BYTES);
      boolean r = signature.verify(signatureBytes);
      if (r) {
        result.setActionResult("Success");
      }
      else {
        result.setActionResult("Error: Signature did not verify correctly");
      }
    }
    catch (Exception e) {
      result.setActionResult(e);
    }

    return result;
  }

  public static class Result {

    @Getter
    private String title;

    @Setter
    private List<Action> actions = new ArrayList<>();

    private Action currentAction = null;

    public Result(final String title) {
      this.title = title;
    }

    public void setActionOperation(final String op) {
      this.currentAction = new Action();
      this.currentAction.setOperation(op);
    }

    public void setActionResult(final String result) {
      if (this.currentAction == null) {
        throw new IllegalStateException();
      }
      this.currentAction.setResult(result);
      this.actions.add(this.currentAction);
      this.currentAction = null;
    }

    public void setActionResult(final Exception result) {
      this.setActionResult(String.format("Error: %s (%s)", result.getMessage(), result.getClass().getSimpleName()));
    }

    public List<Action> getActions() {
      if (this.currentAction != null) {
        if (this.currentAction.getResult() == null) {
          this.currentAction.setResult("Error");
        }
        this.actions.add(this.currentAction);
        this.currentAction = null;
      }
      return this.actions;
    }

    @Data
    public static class Action {
      private String operation;
      private String result;
    }

  }
}
