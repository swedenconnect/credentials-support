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
package se.swedenconnect.security.credential.monitoring;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Supplier;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.credential.KeyPairCredential;

/**
 * The default implementation of the {@link CredentialMonitorBean} interface.
 * <p>
 * The bean can be configured to monitor one, or several, credentials. Note that the credentials being tested must have
 * a test function installed ({@link KeyPairCredential#getTestFunction()} must not be {@code null}.
 * </p>
 * <p>
 * The reason for performing monitoring of credentials is to detect, and possibly fix, the cases where a credential
 * becomes non-functional. This may typically happen if a credential that resides on a hardware device is used. The
 * connection to the device may get lost, and may be fixed by a re-connect. Those types of credentials takes care of
 * their own reloading by implementing {@link KeyPairCredential#reload()}.
 * </p>
 * <p>
 * Since testing a credential, especially those residing on hardware devices, may be a relatively costly operation, the
 * monitor bean also supports configuring "additional credentials for reload" ({@link #setAdditionalForReload(List)}).
 * The use case here is that one credential is configured to be monitored (tested), and if this test fails, we try to
 * reload this credential, but also the "additional credentials for reload". This case may be used if we know that we
 * have a set of credentials that all reside on the same device, and if one is non-functional the others will not work
 * either (bacause of a connection failure). In this case we save computing power and keep testing only one credential,
 * and if that one fails, reloads not only the failing credential but the other ones as well.
 * </p>
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class DefaultCredentialMonitorBean implements CredentialMonitorBean, InitializingBean {

  /** The credentials that should be monitored. */
  private List<KeyPairCredential> credentials;

  /** A list of additional credentials that should be reloaded if a test fails. */
  private List<KeyPairCredential> additionalForReload;

  /** A callback function that is invoked if the test of a credential fails. */
  private BiFunction<KeyPairCredential, Exception, Boolean> failureCallback = null;

  /** A callback function that is invoked if the reloading of a failed credential was successful. */
  private Consumer<KeyPairCredential> reloadSuccessCallback = null;

  /** A callback function that is invoked if the reloading of a failed credential fails. */
  private BiConsumer<KeyPairCredential, Exception> reloadFailureCallback = null;

  /**
   * Default constructor.
   */
  public DefaultCredentialMonitorBean() {
  }

  /**
   * Constructor setting up monitoring of a single credential. If the test for this credential fails a reload attempt
   * will be made ({@link KeyPairCredential#reload()}).
   * 
   * @param credential
   *          the credential to monitor, and possible reload
   */
  public DefaultCredentialMonitorBean(final KeyPairCredential credential) {
    this(credential, null);
  }

  /**
   * Constructor setting up monitoring of a single credential. Since many credentials may share the same underlying
   * device it may in some cases be efficient to only test one credential, and if that fails reload multiple credentials
   * (residing on the same device). The {@code additionalForReload} contains additional credentials to reload if the
   * test of {@code credential} fails.
   * 
   * @param credential
   *          the credential to monitor, and possible reload
   * @param additionalForReload
   *          credentials to reload (in addition to the supplied credential)
   */
  public DefaultCredentialMonitorBean(final KeyPairCredential credential, final List<KeyPairCredential> additionalForReload) {
    if (credential != null) {
      this.credentials = Arrays.asList(credential);
    }
    if (additionalForReload != null && !additionalForReload.isEmpty()) {
      this.additionalForReload = additionalForReload;
    }
  }

  /**
   * Constructor setting up monitoring of the supplied credentials. If the test call for any credential fails, a reload
   * attempt will be made ({@link KeyPairCredential#reload()}) for this credential.
   * 
   * @param credentials
   *          the credentials to monitor, and possible reload
   */
  public DefaultCredentialMonitorBean(final List<KeyPairCredential> credentials) {
    this.credentials = credentials;
  }

  /** {@inheritDoc} */
  @Override
  public void test() {
    boolean additionalReloaded = false;

    for (KeyPairCredential cred : this.credentials) {

      final Supplier<Exception> testFunction = cred.getTestFunction();
      if (testFunction == null) {
        log.trace("Credential '{}' can not be tested - it has no test function installed", cred.getName());
        continue;
      }
      log.trace("Testing credential '{}' ...", cred.getName());
      final Exception testResult = testFunction.get();

      if (testResult == null) {
        log.trace("Test of credential '{}' was successful", cred.getName());
      }
      else {
        Boolean reload = true;
        if (this.failureCallback != null) {
          log.debug("Test of credential '{}' failed - {}", cred.getName(), testResult.getMessage(), testResult);
          reload = this.failureCallback.apply(cred, testResult);
          if (reload != null && !reload.booleanValue()) {
            log.debug("Callback invoked and returned false, meaning no reloading of credential '{}' will occur", cred.getName());
          }
        }
        else {
          log.error("Test of credential '{}' failed - {}", cred.getName(), testResult.getMessage());
          log.debug("Credential failure details", testResult);
        }

        if (reload) {
          this.reload(cred);
          if (this.additionalForReload != null && !additionalReloaded) {
            this.additionalForReload.forEach((c) -> this.reload(c));
            additionalReloaded = true;
          }
        }
      }
    }
  }

  /**
   * Performs reloading of the supplied credential. If the reload is successful, the credential is tested again.
   * 
   * @param credential
   *          the credential to reload
   */
  protected void reload(final KeyPairCredential credential) {
    try {
      log.debug("Reloading credential '{}' ...", credential.getName());
      credential.reload();
      log.debug("Credential '{}' successfully reloaded, will test again ...", credential.getName());

      // OK, we have reloaded the credential. See if it is functional after the reload ...
      //
      final Supplier<Exception> testFunction = credential.getTestFunction();
      Exception testResult = null;
      if (testFunction == null) {
        log.trace("Credential '{}' can not be tested - it has no test function installed", credential.getName());
      }
      else {
        testResult = testFunction.get();
      }
      if (testResult == null) {
        log.debug("Credential '{}' was reloaded and is now functional again ...", credential.getName());
        if (this.reloadSuccessCallback != null) {
          this.reloadSuccessCallback.accept(credential);
        }
      }
      else {
        if (this.reloadFailureCallback != null) {
          log.debug("Test of credential '{}' after it was reloaded failed - {}",
            credential.getName(), testResult.getMessage(), testResult);
          this.reloadFailureCallback.accept(credential, testResult);
        }
        else {
          log.error("Test of credential '{}' after it was reloaded failed - {}", credential.getName(), testResult.getMessage());
          log.debug("Credential failure details", testResult);
        }
      }
    }
    catch (Exception e) {
      if (this.reloadFailureCallback != null) {
        log.debug("Reloading of credential '{}' failed - {}", credential.getName(), e.getMessage(), e);
        this.reloadFailureCallback.accept(credential, e);
      }
      else {
        log.error("Reloading of credential '{}' failed - {}", credential.getName(), e.getMessage());
        log.debug("Credential failure details", e);
      }
    }
  }

  /**
   * Assigns the credential that should be monitored.
   * 
   * @param credential
   *          the credential to be monitored
   */
  public void setCredential(final KeyPairCredential credential) {
    this.credentials = Optional.ofNullable(credential).map(c -> Arrays.asList(c)).orElse(null);
  }

  /**
   * Assigns the credentials that should be monitored.
   * 
   * @param credentials
   *          the credentials to be monitored
   */
  public void setCredentials(final List<KeyPairCredential> credentials) {
    this.credentials = credentials;
  }

  /**
   * Assigns the a list of additional credentials that should be reloaded if a test fails.
   * 
   * @param additionalForReload
   *          additional credentials for reload
   */
  public void setAdditionalForReload(final List<KeyPairCredential> additionalForReload) {
    this.additionalForReload = additionalForReload;
  }

  /**
   * Assigns callback function that is invoked if the test of a credential fails. This is typically useful if some sort
   * of alarm should be issued for failing credentials. The callback returns a boolean that tells whether we should try
   * to reload the failing credential.
   * <p>
   * The default is to not have a callback. In those case the failure is logged (at error level) and the credential is
   * reloaded. Otherwise, the implementation assumes that the callback handles logging.
   * </p>
   * 
   * @param failureCallback
   *          callback function
   */
  public void setFailureCallback(final BiFunction<KeyPairCredential, Exception, Boolean> failureCallback) {
    this.failureCallback = failureCallback;
  }

  /**
   * Assigns a callback function that is invoked if the reloading of a failed credential was successful.
   * 
   * @param reloadSuccessCallback
   *          callback function
   */
  public void setReloadSuccessCallback(final Consumer<KeyPairCredential> reloadSuccessCallback) {
    this.reloadSuccessCallback = reloadSuccessCallback;
  }

  /**
   * Assigns a callback function that is invoked if the reloading of a failed credential fails. This is typically useful
   * if some sort of alarm should be issued for failing reloads.
   * <p>
   * The default is to not have a callback. In those case the failure is logged (at error level). Otherwise, the
   * implementation assumes that the callback handles logging.
   * </p>
   * 
   * @param reloadFailureCallback
   *          callback function
   */
  public void setReloadFailureCallback(final BiConsumer<KeyPairCredential, Exception> reloadFailureCallback) {
    this.reloadFailureCallback = reloadFailureCallback;
  }

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() throws Exception {
    Assert.notEmpty(this.credentials, "No credentials to monitor supplied");
    for (KeyPairCredential c : this.credentials) {
      if (c.getTestFunction() == null) {
        log.warn("Configured credential '{}' has no test function associated - no montoring will be performed", c.getName());
      }
    }
  }

}
