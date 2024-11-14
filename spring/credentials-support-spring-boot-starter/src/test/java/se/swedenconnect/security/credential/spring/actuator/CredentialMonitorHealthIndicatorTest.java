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
package se.swedenconnect.security.credential.spring.actuator;

import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.Status;
import se.swedenconnect.security.credential.monitoring.DefaultCredentialMonitorBeanTest;
import se.swedenconnect.security.credential.spring.actuator.CredentialMonitorHealthIndicator.MonitorStatus;
import se.swedenconnect.security.credential.spring.monitoring.events.FailedCredentialReloadEvent;
import se.swedenconnect.security.credential.spring.monitoring.events.FailedCredentialTestEvent;
import se.swedenconnect.security.credential.spring.monitoring.events.SuccessfulCredentialReloadEvent;
import se.swedenconnect.security.credential.spring.monitoring.events.SuccessfulCredentialTestEvent;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test cases for CredentialMonitorHealthIndicator.
 *
 * @author Martin Lindström
 */
class CredentialMonitorHealthIndicatorTest {

  @Test
  void testEventsNoEventsReceived() {
    final CredentialMonitorHealthIndicator indicator = new CredentialMonitorHealthIndicator();

    // No events received ...
    final Health health = indicator.health();
    assertEquals(Status.UP, health.getStatus());
    assertTrue(health.getDetails().isEmpty());
  }

  @Test
  void testEventsSuccess() {
    final CredentialMonitorHealthIndicator indicator = new CredentialMonitorHealthIndicator();
    indicator.onSuccessfulCredentialTestEvent(new SuccessfulCredentialTestEvent("C1"));
    indicator.onSuccessfulCredentialTestEvent(new SuccessfulCredentialTestEvent("C2"));

    indicator.onSuccessfulCredentialTestEvent(new SuccessfulCredentialTestEvent("C1"));
    indicator.onSuccessfulCredentialTestEvent(new SuccessfulCredentialTestEvent("C2"));

    final Health health = indicator.health();
    assertEquals(Status.UP, health.getStatus());
    final List<MonitorStatus> creds = (List<MonitorStatus>) health.getDetails().get("credentials");
    assertEquals(2, creds.size());
    assertEquals("C1", creds.get(0).getCredentialName());
    assertEquals(MonitorStatus.OK, creds.get(0).getTestResult());
    assertEquals("C2", creds.get(1).getCredentialName());
    assertEquals(MonitorStatus.OK, creds.get(1).getTestResult());
  }

  @Test
  void testEventsFailedTestOkReload() {
    final CredentialMonitorHealthIndicator indicator = new CredentialMonitorHealthIndicator();
    indicator.onSuccessfulCredentialTestEvent(new SuccessfulCredentialTestEvent("C1"));
    indicator.onSuccessfulCredentialTestEvent(new SuccessfulCredentialTestEvent("C2"));

    indicator.onSuccessfulCredentialTestEvent(new SuccessfulCredentialTestEvent("C1"));
    indicator.onFailedCredentialTestEvent(new FailedCredentialTestEvent("C2", "TEST-ERROR", Exception.class.getName()));
    indicator.onSuccessfulCredentialReloadEvent(new SuccessfulCredentialReloadEvent("C2"));

    final Health health = indicator.health();
    assertEquals(CredentialMonitorHealthIndicator.WARNING, health.getStatus());
    final List<MonitorStatus> creds = (List<MonitorStatus>) health.getDetails().get("credentials");
    assertEquals(2, creds.size());
    assertEquals("C1", creds.get(0).getCredentialName());
    assertEquals(MonitorStatus.OK, creds.get(0).getTestResult());
    assertEquals("C2", creds.get(1).getCredentialName());
    assertEquals(MonitorStatus.ERROR, creds.get(1).getTestResult());
    assertEquals("TEST-ERROR", creds.get(1).getTestError());
    assertEquals(Exception.class.getName(), creds.get(1).getTestException());
    assertEquals(MonitorStatus.OK, creds.get(1).getReloadResult());
    assertNull(creds.get(1).getReloadError());
  }

  @Test
  void testEventsFailedTestFailedReload() {
    final CredentialMonitorHealthIndicator indicator = new CredentialMonitorHealthIndicator();
    indicator.onSuccessfulCredentialTestEvent(new SuccessfulCredentialTestEvent("C1"));
    indicator.onFailedCredentialTestEvent(new FailedCredentialTestEvent("C2", "TEST-ERROR", Exception.class.getName()));
    indicator.onFailedCredentialReloadEvent(
        new FailedCredentialReloadEvent("C2", "RELOAD-ERROR", IOException.class.getName()));

    final Health health = indicator.health();
    assertEquals(Status.DOWN, health.getStatus());
    final List<MonitorStatus> creds = (List<MonitorStatus>) health.getDetails().get("credentials");
    assertEquals(2, creds.size());
    assertEquals("C1", creds.get(0).getCredentialName());
    assertEquals(MonitorStatus.OK, creds.get(0).getTestResult());
    assertEquals("C2", creds.get(1).getCredentialName());
    assertEquals(MonitorStatus.ERROR, creds.get(1).getTestResult());
    assertEquals("TEST-ERROR", creds.get(1).getTestError());
    assertEquals(Exception.class.getName(), creds.get(1).getTestException());
    assertEquals(MonitorStatus.ERROR, creds.get(1).getReloadResult());
    assertEquals("RELOAD-ERROR", creds.get(1).getReloadError());
    assertEquals(IOException.class.getName(), creds.get(1).getReloadException());
  }

  @Test
  void testEventsNoTestEventReceivedReloadSuccess() {
    final CredentialMonitorHealthIndicator indicator = new CredentialMonitorHealthIndicator();
    indicator.onSuccessfulCredentialReloadEvent(new SuccessfulCredentialReloadEvent("C2"));

    final Health health = indicator.health();
    assertEquals(CredentialMonitorHealthIndicator.WARNING, health.getStatus());
    final MonitorStatus cred = ((List<MonitorStatus>) health.getDetails().get("credentials")).get(0);

    assertEquals("C2", cred.getCredentialName());
    assertEquals(MonitorStatus.ERROR, cred.getTestResult());
    assertEquals("Unknown", cred.getTestError());
    assertNull(cred.getTestException());
    assertEquals(MonitorStatus.OK, cred.getReloadResult());
    assertNull(cred.getReloadError());
  }

  @Test
  void testEventsNoTestEventReceivedReloadFailure() {
    final CredentialMonitorHealthIndicator indicator = new CredentialMonitorHealthIndicator();
    indicator.onFailedCredentialReloadEvent(
        new FailedCredentialReloadEvent("C2", "RELOAD-ERROR", Exception.class.getName()));

    final Health health = indicator.health();
    assertEquals(Status.DOWN, health.getStatus());
    final MonitorStatus cred = ((List<MonitorStatus>) health.getDetails().get("credentials")).get(0);

    assertEquals("C2", cred.getCredentialName());
    assertEquals(MonitorStatus.ERROR, cred.getTestResult());
    assertEquals("Unknown", cred.getTestError());
    assertNull(cred.getTestException());
    assertEquals(MonitorStatus.ERROR, cred.getReloadResult());
    assertEquals("RELOAD-ERROR", cred.getReloadError());
    assertEquals(Exception.class.getName(), cred.getReloadException());
  }

  /**
   * See {@link se.swedenconnect.security.credential.monitoring.DefaultCredentialMonitorBeanTest}.
   */
  @Test
  void testMonitorReloadSuccess() {
    final DefaultCredentialMonitorBeanTest.TestFunction tf1 = new DefaultCredentialMonitorBeanTest.TestFunction();
    tf1.setError(new SecurityException("1 failed"), true);
    final DefaultCredentialMonitorBeanTest.TestCredential cred =
        new DefaultCredentialMonitorBeanTest.TestCredential("1");
    cred.setTestFunction(tf1);

    final DefaultCredentialMonitorBeanTest.TestFunction tf2 = new DefaultCredentialMonitorBeanTest.TestFunction();
    final DefaultCredentialMonitorBeanTest.TestCredential cred2 =
        new DefaultCredentialMonitorBeanTest.TestCredential("2");
    cred2.setTestFunction(tf2);

    final CredentialMonitorHealthIndicator indicator = new CredentialMonitorHealthIndicator(List.of(cred, cred2));
    final Health health = indicator.health();

    assertEquals(CredentialMonitorHealthIndicator.WARNING, health.getStatus());
    final List<MonitorStatus> creds = (List<MonitorStatus>) health.getDetails().get("credentials");
    assertEquals(2, creds.size());
    assertEquals("1", creds.get(0).getCredentialName());
    assertEquals(MonitorStatus.ERROR, creds.get(0).getTestResult());
    assertEquals(MonitorStatus.OK, creds.get(0).getReloadResult());
    assertEquals("2", creds.get(1).getCredentialName());
    assertEquals(MonitorStatus.OK, creds.get(1).getTestResult());
  }

  @Test
  void testMonitorReloadError() {
    final DefaultCredentialMonitorBeanTest.TestFunction tf1 = new DefaultCredentialMonitorBeanTest.TestFunction();
    tf1.setError(new SecurityException("1 failed"), false);
    final DefaultCredentialMonitorBeanTest.TestCredential cred =
        new DefaultCredentialMonitorBeanTest.TestCredential("1");
    cred.setTestFunction(tf1);

    final DefaultCredentialMonitorBeanTest.TestFunction tf2 = new DefaultCredentialMonitorBeanTest.TestFunction();
    final DefaultCredentialMonitorBeanTest.TestCredential cred2 =
        new DefaultCredentialMonitorBeanTest.TestCredential("2");
    cred2.setTestFunction(tf2);

    final CredentialMonitorHealthIndicator indicator = new CredentialMonitorHealthIndicator(List.of(cred, cred2));
    final Health health = indicator.health();

    assertEquals(Status.DOWN, health.getStatus());
    final List<MonitorStatus> creds = (List<MonitorStatus>) health.getDetails().get("credentials");
    assertEquals(2, creds.size());
    assertEquals("1", creds.get(0).getCredentialName());
    assertEquals(MonitorStatus.ERROR, creds.get(0).getTestResult());
    assertEquals(MonitorStatus.ERROR, creds.get(0).getReloadResult());
    assertEquals("2", creds.get(1).getCredentialName());
    assertEquals(MonitorStatus.OK, creds.get(1).getTestResult());
  }

}
