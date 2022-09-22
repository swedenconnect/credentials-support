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
package se.swedenconnect.security.credential.monitoring;

import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

import lombok.Getter;
import lombok.Setter;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
import se.swedenconnect.security.credential.ReloadablePkiCredential;

/**
 * Test cases for DefaultCredentialMonitorBean.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultCredentialMonitorBeanTest {

  @Test
  public void testReloadSuccess() throws Exception {
    TestFunction tf1 = new TestFunction();
    tf1.setError(new SecurityException("1 failed"), true);
    TestCredential cred = new TestCredential("1");
    cred.setTestFunction(tf1);

    // Will not be tested - only reloaded
    TestFunction tf2 = new TestFunction();
    TestCredential cred2 = new TestCredential("2");
    cred2.setTestFunction(tf2);

    TestCredential cred3 = new TestCredential("3");

    SuccessConsumer successConsumer = new SuccessConsumer();
    DefaultCredentialMonitorBean monitor = new DefaultCredentialMonitorBean(cred, Arrays.asList(cred2, cred3));
    monitor.setReloadSuccessCallback(successConsumer);
    monitor.afterPropertiesSet();

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

    successConsumer = new SuccessConsumer();

    monitor = new DefaultCredentialMonitorBean();
    monitor.setCredential(cred);
    monitor.setAdditionalForReload(Arrays.asList(cred2, cred3));
    monitor.setReloadSuccessCallback(successConsumer);
    monitor.afterPropertiesSet();

    monitor.test();

    assertEquals(1, cred.getReloadCalled());
    assertEquals(2, tf1.getTestCalled());

    assertEquals(1, cred2.getReloadCalled());
    assertEquals(1, tf2.getTestCalled());

    assertEquals(1, cred3.getReloadCalled());

    assertEquals(Arrays.asList("1", "2", "3"), successConsumer.getCredentialNames());
  }

  @Test
  public void testReloadSuccessMultiple() throws Exception {
    TestFunction tf1 = new TestFunction();
    tf1.setError(new SecurityException("1 failed"), true);
    TestCredential cred = new TestCredential("1");
    cred.setTestFunction(tf1);

    TestFunction tf2 = new TestFunction();
    tf2.setError(new SecurityException("2 failed"), true);
    TestCredential cred2 = new TestCredential("2");
    cred2.setTestFunction(tf2);

    SuccessConsumer successConsumer = new SuccessConsumer();
    DefaultCredentialMonitorBean monitor = new DefaultCredentialMonitorBean();
    monitor.setCredentials(Arrays.asList(cred, cred2));
    monitor.setReloadSuccessCallback(successConsumer);
    monitor.afterPropertiesSet();

    monitor.test();

    assertEquals(1, cred.getReloadCalled());
    assertEquals(2, tf1.getTestCalled());

    assertEquals(1, cred2.getReloadCalled());
    assertEquals(2, tf2.getTestCalled());

    assertEquals(Arrays.asList("1", "2"), successConsumer.getCredentialNames());
  }

  @Test
  public void testTestSuccess() throws Exception {
    TestFunction tf1 = new TestFunction();
    TestCredential cred = new TestCredential("1");
    cred.setTestFunction(tf1);

    TestFunction tf2 = new TestFunction();
    TestCredential cred2 = new TestCredential("2");
    cred2.setTestFunction(tf2);

    DefaultCredentialMonitorBean monitor = new DefaultCredentialMonitorBean(Arrays.asList(cred, cred2));
    SuccessConsumer successConsumer = new SuccessConsumer();
    monitor.setReloadSuccessCallback(successConsumer);
    monitor.afterPropertiesSet();

    monitor.test();

    assertEquals(0, cred.getReloadCalled());
    assertEquals(1, tf1.getTestCalled());

    assertEquals(0, cred2.getReloadCalled());
    assertEquals(1, tf2.getTestCalled());

    assertTrue(successConsumer.getCredentialNames().isEmpty());
  }

  @Test
  public void testReloadFailbackNoReload() throws Exception {
    TestFunction tf1 = new TestFunction();
    tf1.setError(new SecurityException("1 failed"), true);

    TestCredential cred = new TestCredential();
    cred.setTestFunction(tf1);

    DefaultCredentialMonitorBean monitor = new DefaultCredentialMonitorBean(cred);
    monitor.setFailureCallback((c, e) -> Boolean.FALSE);
    monitor.afterPropertiesSet();
    monitor.test();

    assertEquals(0, cred.getReloadCalled());

    // Should be the same if the callback returns null
    tf1 = new TestFunction();
    tf1.setError(new SecurityException("1 failed"), true);

    cred = new TestCredential();
    cred.setTestFunction(tf1);

    monitor = new DefaultCredentialMonitorBean(cred);
    monitor.setFailureCallback((c, e) -> null);
    monitor.afterPropertiesSet();
    monitor.test();

    assertEquals(0, cred.getReloadCalled());
  }

  @Test
  public void testReloadFailbackOrderedReload() throws Exception {
    TestFunction tf1 = new TestFunction();
    tf1.setError(new SecurityException("1 failed"), true);

    TestCredential cred = new TestCredential();
    cred.setTestFunction(tf1);

    DefaultCredentialMonitorBean monitor = new DefaultCredentialMonitorBean(cred);
    monitor.setFailureCallback((c, e) -> Boolean.TRUE);
    monitor.afterPropertiesSet();
    monitor.test();

    assertEquals(1, cred.getReloadCalled());
  }

  @Test
  public void testReloadFailure() throws Exception {

    TestCredential cred = new TestCredential();
    TestFunction tf1 = new TestFunction();
    tf1.setError(new SecurityException("1 failed"), false);
    cred.setTestFunction(tf1);
    cred.setReloadException(new SecurityException());

    ReloadFailureCallback rfc = new ReloadFailureCallback();

    DefaultCredentialMonitorBean monitor = new DefaultCredentialMonitorBean();
    monitor.setCredential(cred);
    monitor.setReloadFailureCallback(rfc);
    monitor.afterPropertiesSet();

    monitor.test();

    assertEquals(SecurityException.class, rfc.getReceivedException().getClass());

    // If we don't have a callback things are only logged ...
    monitor.setReloadFailureCallback(null);
    monitor.test();
  }

  @Test
  public void testTestAfterReloadFails() throws Exception {
    TestCredential cred = new TestCredential();
    TestFunction tf1 = new TestFunction();
    tf1.setError(new KeyStoreException("1 failed"), false);
    cred.setTestFunction(tf1);

    ReloadFailureCallback rfc = new ReloadFailureCallback();

    DefaultCredentialMonitorBean monitor = new DefaultCredentialMonitorBean();
    monitor.setCredential(cred);
    monitor.setReloadFailureCallback(rfc);
    monitor.afterPropertiesSet();

    monitor.test();

    assertEquals(KeyStoreException.class, rfc.getReceivedException().getClass());

    // If we don't have a callback things are only logged ...
    monitor.setReloadFailureCallback(null);
    monitor.test();
  }

  @Test
  public void testMissingCredential() throws Exception {
    assertThrows(IllegalArgumentException.class, () -> {
      DefaultCredentialMonitorBean monitor = new DefaultCredentialMonitorBean(null, Arrays.asList());
      monitor.afterPropertiesSet();
    });
  }

  @Test
  public void testNoTestFunction() throws Exception {
    TestCredential cred = new TestCredential();
    DefaultCredentialMonitorBean monitor = new DefaultCredentialMonitorBean(cred);
    monitor.afterPropertiesSet();
    monitor.test();

    assertEquals(0, cred.getReloadCalled());
  }

  public static class SuccessConsumer implements Consumer<ReloadablePkiCredential> {

    @Getter
    private List<String> credentialNames = new ArrayList<>();

    @Override
    public void accept(ReloadablePkiCredential t) {
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
    public Exception apply(ReloadablePkiCredential t) {
      this.testCalled++;
      Exception ret = this.error;
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
    public void accept(ReloadablePkiCredential t, Exception u) {
      this.receivedException = u;
    }

  }

  public static class TestCredential implements ReloadablePkiCredential {

    @Setter
    private String name = "TestCredential";

    @Getter
    private int reloadCalled = 0;

    @Setter
    private Exception reloadException = null;

    private Function<ReloadablePkiCredential, Exception> testFunction;

    public TestCredential() {
    }

    public TestCredential(final String name) {
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
    public PublicKey getPublicKey() {
      return null;
    }

    @Override
    public X509Certificate getCertificate() {
      return null;
    }

    @Override
    public List<X509Certificate> getCertificateChain() {
      return null;
    }

    @Override
    public PrivateKey getPrivateKey() {
      return null;
    }

    @Override
    public String getName() {
      return this.name;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
    }

    @Override
    public void destroy() throws Exception {
    }

    @Override
    public void setCertificate(final X509Certificate certificate) {
    }

    @Override
    public void setCertificateChain(final List<X509Certificate> certificates) {
    }

  }

}
