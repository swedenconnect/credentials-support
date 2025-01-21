/*
 * Copyright 2020-2025 Sweden Connect
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
import lombok.Getter;
import lombok.Setter;
import org.junit.jupiter.api.Test;
import se.swedenconnect.security.credential.ReloadablePkiCredential;

import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test cases for DefaultCredentialMonitorBean.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultCredentialMonitorBeanTest {

  @Test
  void testReloadSuccess() {
    TestFunction tf1 = new TestFunction();
    tf1.setError(new SecurityException("1 failed"), true);
    TestCredential cred = new TestCredential("1");
    cred.setTestFunction(tf1);

    // Will not be tested - only reloaded
    TestFunction tf2 = new TestFunction();
    TestCredential cred2 = new TestCredential("2");
    cred2.setTestFunction(tf2);

    TestCredential cred3 = new TestCredential("3");
    cred3.setTestFunction(new TestFunction());

    SuccessConsumer successConsumer = new SuccessConsumer();
    DefaultCredentialMonitorBean monitor = new DefaultCredentialMonitorBean(cred, Arrays.asList(cred2, cred3));
    monitor.setReloadSuccessCallback(successConsumer);

    monitor.test();

    assertEquals(1, cred.getReloadCalled());
    assertEquals(2, tf1.getTestCalled());

    assertEquals(1, cred2.getReloadCalled());
    assertEquals(1, tf2.getTestCalled());

    assertEquals(1, cred3.getReloadCalled());

    assertEquals(Arrays.asList("1", "2", "3"), successConsumer.getCredentialNames());

    // The same with setters
    tf1 = new TestFunction();
    tf1.setError(new SecurityException("1 failed"), true);
    cred = new TestCredential("1");
    cred.setTestFunction(tf1);

    tf2 = new TestFunction();
    cred2 = new TestCredential("2");
    cred2.setTestFunction(tf2);

    cred3 = new TestCredential("3");
    cred3.setTestFunction(new TestFunction());

    successConsumer = new SuccessConsumer();

    monitor = new DefaultCredentialMonitorBean(cred, List.of(cred2, cred3));
    monitor.setReloadSuccessCallback(successConsumer);

    monitor.test();

    assertEquals(1, cred.getReloadCalled());
    assertEquals(2, tf1.getTestCalled());

    assertEquals(1, cred2.getReloadCalled());
    assertEquals(1, tf2.getTestCalled());

    assertEquals(1, cred3.getReloadCalled());

    assertEquals(Arrays.asList("1", "2", "3"), successConsumer.getCredentialNames());
  }

  @Test
  void testReloadSuccessMultiple() {
    final TestFunction tf1 = new TestFunction();
    tf1.setError(new SecurityException("1 failed"), true);
    final TestCredential cred = new TestCredential("1");
    cred.setTestFunction(tf1);

    final TestFunction tf2 = new TestFunction();
    tf2.setError(new SecurityException("2 failed"), true);
    final TestCredential cred2 = new TestCredential("2");
    cred2.setTestFunction(tf2);

    final SuccessConsumer successConsumer = new SuccessConsumer();
    final DefaultCredentialMonitorBean monitor = new DefaultCredentialMonitorBean(Arrays.asList(cred, cred2));
    monitor.setReloadSuccessCallback(successConsumer);

    monitor.test();

    assertEquals(1, cred.getReloadCalled());
    assertEquals(2, tf1.getTestCalled());

    assertEquals(1, cred2.getReloadCalled());
    assertEquals(2, tf2.getTestCalled());

    assertEquals(Arrays.asList("1", "2"), successConsumer.getCredentialNames());
  }

  @Test
  void testTestSuccess() {
    final TestFunction tf1 = new TestFunction();
    final TestCredential cred = new TestCredential("1");
    cred.setTestFunction(tf1);

    final TestFunction tf2 = new TestFunction();
    final TestCredential cred2 = new TestCredential("2");
    cred2.setTestFunction(tf2);

    final DefaultCredentialMonitorBean monitor = new DefaultCredentialMonitorBean(Arrays.asList(cred, cred2));
    final SuccessConsumer successConsumer = new SuccessConsumer();
    monitor.setReloadSuccessCallback(successConsumer);

    monitor.test();

    assertEquals(0, cred.getReloadCalled());
    assertEquals(1, tf1.getTestCalled());

    assertEquals(0, cred2.getReloadCalled());
    assertEquals(1, tf2.getTestCalled());

    assertTrue(successConsumer.getCredentialNames().isEmpty());
  }

  @Test
  void testReloadFailbackNoReload() {
    TestFunction tf1 = new TestFunction();
    tf1.setError(new SecurityException("1 failed"), true);

    TestCredential cred = new TestCredential();
    cred.setTestFunction(tf1);

    DefaultCredentialMonitorBean monitor = new DefaultCredentialMonitorBean(cred);
    monitor.setFailureCallback((c, e) -> Boolean.FALSE);
    monitor.test();

    assertEquals(0, cred.getReloadCalled());

    // Should be the same if the callback returns null
    tf1 = new TestFunction();
    tf1.setError(new SecurityException("1 failed"), true);

    cred = new TestCredential();
    cred.setTestFunction(tf1);

    monitor = new DefaultCredentialMonitorBean(cred);
    monitor.setFailureCallback((c, e) -> null);
    monitor.test();

    assertEquals(0, cred.getReloadCalled());
  }

  @Test
  void testReloadFailbackOrderedReload() {
    final TestFunction tf1 = new TestFunction();
    tf1.setError(new SecurityException("1 failed"), true);

    final TestCredential cred = new TestCredential();
    cred.setTestFunction(tf1);

    final DefaultCredentialMonitorBean monitor = new DefaultCredentialMonitorBean(cred);
    monitor.setFailureCallback((c, e) -> Boolean.TRUE);
    monitor.test();

    assertEquals(1, cred.getReloadCalled());
  }

  @Test
  void testReloadFailure() {

    final TestCredential cred = new TestCredential();
    final TestFunction tf1 = new TestFunction();
    tf1.setError(new SecurityException("1 failed"), false);
    cred.setTestFunction(tf1);
    cred.setReloadException(new SecurityException());

    final ReloadFailureCallback rfc = new ReloadFailureCallback();

    final DefaultCredentialMonitorBean monitor = new DefaultCredentialMonitorBean(cred);
    monitor.setReloadFailureCallback(rfc);

    monitor.test();

    assertEquals(SecurityException.class, rfc.getReceivedException().getClass());

    // If we don't have a callback things are only logged ...
    monitor.setReloadFailureCallback(null);
    monitor.test();
  }

  @Test
  void testTestAfterReloadFails() {
    final TestCredential cred = new TestCredential();
    final TestFunction tf1 = new TestFunction();
    tf1.setError(new KeyStoreException("1 failed"), false);
    cred.setTestFunction(tf1);

    final ReloadFailureCallback rfc = new ReloadFailureCallback();

    final DefaultCredentialMonitorBean monitor = new DefaultCredentialMonitorBean(cred);
    monitor.setReloadFailureCallback(rfc);

    monitor.test();

    assertEquals(KeyStoreException.class, rfc.getReceivedException().getClass());

    // If we don't have a callback things are only logged ...
    monitor.setReloadFailureCallback(null);
    monitor.test();
  }

  @Test
  void testMissingCredential() {
    assertThrows(NullPointerException.class, () -> new DefaultCredentialMonitorBean(null, List.of()));
  }

  @Test
  void testNoTestFunction() {
    final TestCredential cred = new TestCredential();
    final DefaultCredentialMonitorBean monitor = new DefaultCredentialMonitorBean(cred);
    monitor.test();

    assertEquals(0, cred.getReloadCalled());
  }

  public static class SuccessConsumer implements Consumer<ReloadablePkiCredential> {

    @Getter
    private final List<String> credentialNames = new ArrayList<>();

    @Override
    public void accept(final ReloadablePkiCredential t) {
      this.credentialNames.add(t.getName());
    }
  }

  public static class TestFunction implements Function<ReloadablePkiCredential, Exception> {

    @Getter
    private int testCalled = 0;

    private Exception error = null;
    private boolean failOnlyOnce = true;

    public TestFunction() {
    }

    public void setError(final Exception error, final boolean failOnlyOnce) {
      this.error = error;
      this.failOnlyOnce = failOnlyOnce;
    }

    @Override
    public Exception apply(final ReloadablePkiCredential t) {
      this.testCalled++;
      final Exception ret = this.error;
      if (this.error != null && this.failOnlyOnce) {
        this.error = null;
      }
      return ret;
    }
  }

  public static class ReloadFailureCallback implements BiConsumer<ReloadablePkiCredential, Exception> {

    @Getter
    private Exception receivedException;

    @Override
    public void accept(final ReloadablePkiCredential t, final Exception u) {
      this.receivedException = u;
    }
  }

  public static class TestCredential implements ReloadablePkiCredential {

    private final Metadata metadata;

    @Setter
    private String name = "TestCredential";

    @Getter
    private int reloadCalled = 0;

    @Setter
    private Exception reloadException = null;

    private Function<ReloadablePkiCredential, Exception> testFunction;

    public TestCredential() {
      this.metadata = new Metadata() {
        private final Map<String, Object> properties = new HashMap<>();

        @Nonnull
        @Override
        public Map<String, Object> getProperties() {
          return this.properties;
        }
      };
    }

    public TestCredential(final String name) {
      this();
      this.name = name;
    }

    @Override
    public Supplier<Exception> getTestFunction() {
      if (this.testFunction != null) {
        return () -> this.testFunction.apply(this);
      }
      else {
        return null;
      }
    }

    public void setTestFunction(final Function<ReloadablePkiCredential, Exception> testFunction) {
      this.testFunction = testFunction;
    }

    @Override
    public void reload() throws Exception {
      this.reloadCalled++;
      if (this.reloadException != null) {
        throw this.reloadException;
      }
    }

    @Override
    @Nonnull
    public PublicKey getPublicKey() {
      return null;
    }

    @Override
    @Nullable
    public X509Certificate getCertificate() {
      return null;
    }

    @Override
    @Nonnull
    public List<X509Certificate> getCertificateChain() {
      return List.of();
    }

    @Override
    @Nonnull
    public PrivateKey getPrivateKey() {
      return null;
    }

    @Nonnull
    @Override
    public Metadata getMetadata() {
      return this.metadata;
    }

    @Override
    @Nonnull
    public String getName() {
      return this.name;
    }
  }

}
