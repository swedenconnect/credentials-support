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

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.swedenconnect.security.credential.ReloadablePkiCredential;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * The default implementation of the {@link CredentialMonitorBean} interface.
 * <p>
 * The bean can be configured to monitor one, or several, credentials. Note that the credentials being tested must
 * implement the {@link ReloadablePkiCredential} interface and have a test function installed
 * ({@link ReloadablePkiCredential#getTestFunction()} must not be {@code null}.
 * </p>
 * <p>
 * The reason for performing monitoring of credentials is to detect, and possibly fix, the cases where a credential
 * becomes non-functional. This may typically happen if a credential that resides on a hardware device is used. The
 * connection to the device may get lost, and may be fixed by a re-connect. Those types of credentials takes care of
 * their own reloading by implementing {@link ReloadablePkiCredential#reload()}.
 * </p>
 * <p>
 * Since testing a credential, especially those residing on hardware devices, may be a relatively costly operation, the
 * monitor bean also supports configuring "additional credentials for reload"
 * ({@link #DefaultCredentialMonitorBean(ReloadablePkiCredential, List)}). The use case here is that one credential is
 * configured to be monitored (tested), and if this test fails, we try to reload this credential, but also the
 * "additional credentials for reload". This case may be used if we know that we have a set of credentials that all
 * reside on the same device, and if one is non-functional the others will not work either (bacause of a connection
 * failure). In this case we save computing power and keep testing only one credential, and if that one fails, reloads
 * not only the failing credential but the other ones as well.
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultCredentialMonitorBean implements CredentialMonitorBean {

  /** Logging instance. */
  private static final Logger log = LoggerFactory.getLogger(DefaultCredentialMonitorBean.class);

  /** The credentials that should be monitored. */
  private final List<ReloadablePkiCredential> credentials;

  /** A list of additional credentials that should be reloaded if a test fails. */
  private final List<ReloadablePkiCredential> additionalForReload;

  /** A callback for successful tests. */
  private Consumer<ReloadablePkiCredential> testSuccessCallback;

  /** A callback function that is invoked if the test of a credential fails. */
  private BiFunction<ReloadablePkiCredential, Exception, Boolean> failureCallback;

  /** A callback function that is invoked if the reloading of a failed credential was successful. */
  private Consumer<ReloadablePkiCredential> reloadSuccessCallback;

  /** A callback function that is invoked if the reloading of a failed credential fails. */
  private BiConsumer<ReloadablePkiCredential, Exception> reloadFailureCallback;

  /**
   * Constructor setting up monitoring of a single credential. If the test for this credential fails a reload attempt
   * will be made ({@link ReloadablePkiCredential#reload()}).
   *
   * @param credential the credential to monitor, and possible reload
   */
  public DefaultCredentialMonitorBean(@Nonnull final ReloadablePkiCredential credential) {
    this(credential, null);
  }

  /**
   * Constructor setting up monitoring of a single credential. Since many credentials may share the same underlying
   * device it may in some cases be efficient to only test one credential, and if that fails reload multiple credentials
   * (residing on the same device). The {@code additionalForReload} contains additional credentials to reload if the
   * test of {@code credential} fails.
   *
   * @param credential the credential to monitor, and possible reload
   * @param additionalForReload credentials to reload (in addition to the supplied credential)
   */
  public DefaultCredentialMonitorBean(@Nonnull final ReloadablePkiCredential credential,
      @Nullable final List<ReloadablePkiCredential> additionalForReload) {

    this.credentials = List.of(Objects.requireNonNull(credential, "credential must not be null"));
    if (credential.getTestFunction() == null) {
      log.warn("Configured credential '{}' has no test function associated - no montoring will be performed",
          credential.getName());
    }
    this.additionalForReload = Optional.ofNullable(additionalForReload)
        .filter(a -> !a.isEmpty())
        .map(Collections::unmodifiableList)
        .orElse(null);
    if (this.additionalForReload != null) {
      this.additionalForReload.forEach(c -> {
        if (c.getTestFunction() == null) {
          log.warn("Credential '{}' was configured to be reloaded, but has not support for reloading",
              credential.getName());
        }
      });
    }
  }

  /**
   * Constructor setting up monitoring of the supplied credentials. If the test call for any credential fails, a reload
   * attempt will be made ({@link ReloadablePkiCredential#reload()}) for this credential.
   *
   * @param credentials the credentials to monitor, and possible reload
   */
  public DefaultCredentialMonitorBean(final List<ReloadablePkiCredential> credentials) {
    this.credentials = Optional.of(Objects.requireNonNull(credentials, "credentials must not be null"))
        .filter(a -> !a.isEmpty())
        .map(Collections::unmodifiableList)
        .orElseGet(() -> {
          log.info("Monitor bean initialized with empty list of credentials - no montoring will be performed");
          return Collections.emptyList();
        });
    this.additionalForReload = null;
    this.credentials.forEach(c -> {
      if (c.getTestFunction() == null) {
        log.warn("Configured credential '{}' has no test function associated - no montoring will be performed",
            c.getName());
      }
    });
  }

  /** {@inheritDoc} */
  @Override
  public void test() {
    boolean additionalReloaded = false;

    for (final ReloadablePkiCredential cred : this.credentials) {

      final Supplier<Exception> testFunction = cred.getTestFunction();
      if (testFunction == null) {
        log.trace("Credential '{}' can not be tested - it has no test function installed", cred.getName());
        continue;
      }
      log.trace("Testing credential '{}' ...", cred.getName());
      final Exception testResult = testFunction.get();

      if (testResult == null) {
        log.trace("Test of credential '{}' was successful", cred.getName());
        Optional.ofNullable(this.testSuccessCallback).ifPresent(callback -> callback.accept(cred));
      }
      else {
        Boolean reload = true;
        if (this.failureCallback != null) {
          log.debug("Test of credential '{}' failed - {}", cred.getName(), testResult.getMessage(), testResult);
          reload = this.failureCallback.apply(cred, testResult);
          if (reload == null) {
            log.warn("Failure callback returned null - assuming FALSE");
            reload = false;
          }
          if (!reload) {
            log.debug("Callback invoked and returned false, meaning no reloading of credential '{}' will occur",
                cred.getName());
          }
        }
        else {
          log.error("Test of credential '{}' failed - {}", cred.getName(), testResult.getMessage());
          log.debug("Credential failure details", testResult);
        }

        if (reload) {
          this.reload(cred);
          if (!additionalReloaded) {
            if (this.additionalForReload != null) {
              this.additionalForReload.forEach(this::reload);
            }
            additionalReloaded = true;
          }
        }
      }
    }
  }

  /**
   * Performs reloading of the supplied credential. If the reload is successful, the credential is tested again.
   *
   * @param credential the credential to reload
   */
  protected void reload(final ReloadablePkiCredential credential) {
    try {
      if (credential.getTestFunction() == null) {
        log.warn("Credential '{}' has no test function installed - cannot reload", credential.getName());
        return;
      }

      log.debug("Reloading credential '{}' ...", credential.getName());
      credential.reload();
      log.debug("Credential '{}' successfully reloaded, will test again ...", credential.getName());

      // OK, we have reloaded the credential. See if it is functional after the reload ...
      //
      final Supplier<Exception> testFunction = credential.getTestFunction();
      final Exception testResult = testFunction.get();
      if (testResult == null) {
        log.debug("Credential '{}' was reloaded and is now functional again ...", credential.getName());
        Optional.ofNullable(this.reloadSuccessCallback).ifPresent(callback -> callback.accept(credential));
      }
      else {
        log.debug("Test of credential '{}' after it was reloaded failed - {}",
            credential.getName(), testResult.getMessage(), testResult);
        Optional.ofNullable(this.reloadFailureCallback).ifPresent(callback -> callback.accept(credential, testResult));
      }
    }
    catch (final Exception e) {
      log.info("Reloading of credential '{}' failed - {}", credential.getName(), e.getMessage(), e);
      Optional.ofNullable(this.reloadFailureCallback).ifPresent(callback -> callback.accept(credential, e));
    }
  }

  /**
   * Assigns a callback function that is invoked if the credential is successfully tested.
   *
   * @param testSuccessCallback callback
   */
  public void setTestSuccessCallback(final Consumer<ReloadablePkiCredential> testSuccessCallback) {
    this.testSuccessCallback = testSuccessCallback;
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
   * @param failureCallback callback function
   */
  public void setFailureCallback(final BiFunction<ReloadablePkiCredential, Exception, Boolean> failureCallback) {
    this.failureCallback = failureCallback;
  }

  /**
   * Assigns a callback function that is invoked if the reloading of a failed credential was successful.
   *
   * @param reloadSuccessCallback callback function
   */
  public void setReloadSuccessCallback(final Consumer<ReloadablePkiCredential> reloadSuccessCallback) {
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
   * @param reloadFailureCallback callback function
   */
  public void setReloadFailureCallback(final BiConsumer<ReloadablePkiCredential, Exception> reloadFailureCallback) {
    this.reloadFailureCallback = reloadFailureCallback;
  }

}
