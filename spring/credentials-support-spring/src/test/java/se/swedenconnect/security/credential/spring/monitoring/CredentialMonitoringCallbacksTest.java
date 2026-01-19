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
package se.swedenconnect.security.credential.spring.monitoring;

import jakarta.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.context.ApplicationEventPublisher;
import se.swedenconnect.security.credential.ReloadablePkiCredential;
import se.swedenconnect.security.credential.spring.monitoring.events.FailedCredentialReloadEvent;
import se.swedenconnect.security.credential.spring.monitoring.events.FailedCredentialTestEvent;
import se.swedenconnect.security.credential.spring.monitoring.events.SuccessfulCredentialReloadEvent;
import se.swedenconnect.security.credential.spring.monitoring.events.SuccessfulCredentialTestEvent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test cases for CredentialMonitoringCallbacks.
 *
 * @author Martin Lindström
 */
class CredentialMonitoringCallbacksTest {

  @Test
  void testTestSuccessCallback() {
    final Publisher publisher = new Publisher();
    final CredentialMonitoringCallbacks callbacks = new CredentialMonitoringCallbacks(publisher);

    final ReloadablePkiCredential credential = Mockito.mock(ReloadablePkiCredential.class);
    Mockito.when(credential.getName()).thenReturn("name");

    callbacks.getTestSuccessCallback().accept(credential);

    final Object event = publisher.getLatestEvent();
    assertNotNull(event);
    assertTrue(event instanceof SuccessfulCredentialTestEvent);
    assertEquals("name", ((SuccessfulCredentialTestEvent) event).getCredentialName());
  }

  @Test
  void testTestFailureCallback() {
    final Publisher publisher = new Publisher();
    final CredentialMonitoringCallbacks callbacks = new CredentialMonitoringCallbacks(publisher);

    final ReloadablePkiCredential credential = Mockito.mock(ReloadablePkiCredential.class);
    Mockito.when(credential.getName()).thenReturn("name");

    final SecurityException exception = new SecurityException("error");

    final boolean result = callbacks.getTestFailureCallback().apply(credential, exception);

    assertTrue(result);
    final Object event = publisher.getLatestEvent();
    assertNotNull(event);
    assertTrue(event instanceof FailedCredentialTestEvent);
    assertEquals("name", ((FailedCredentialTestEvent) event).getCredentialName());
    assertEquals("error", ((FailedCredentialTestEvent) event).getError());
    assertEquals(SecurityException.class.getName(), ((FailedCredentialTestEvent) event).getException());
  }

  @Test
  void testReloadSuccessCallback() {
    final Publisher publisher = new Publisher();
    final CredentialMonitoringCallbacks callbacks = new CredentialMonitoringCallbacks(publisher);

    final ReloadablePkiCredential credential = Mockito.mock(ReloadablePkiCredential.class);
    Mockito.when(credential.getName()).thenReturn("name");

    callbacks.getReloadSuccessCallback().accept(credential);

    final Object event = publisher.getLatestEvent();
    assertNotNull(event);
    assertTrue(event instanceof SuccessfulCredentialReloadEvent);
    assertEquals("name", ((SuccessfulCredentialReloadEvent) event).getCredentialName());
  }

  @Test
  void testReloadFailureCallback() {
    final Publisher publisher = new Publisher();
    final CredentialMonitoringCallbacks callbacks = new CredentialMonitoringCallbacks(publisher);

    final ReloadablePkiCredential credential = Mockito.mock(ReloadablePkiCredential.class);
    Mockito.when(credential.getName()).thenReturn("name");

    final SecurityException exception = new SecurityException("error");

    callbacks.getReloadFailureCallback().accept(credential, exception);

    final Object event = publisher.getLatestEvent();
    assertNotNull(event);
    assertTrue(event instanceof FailedCredentialReloadEvent);
    assertEquals("name", ((FailedCredentialReloadEvent) event).getCredentialName());
    assertEquals("error", ((FailedCredentialReloadEvent) event).getError());
    assertEquals(SecurityException.class.getName(), ((FailedCredentialReloadEvent) event).getException());
  }

  private static class Publisher implements ApplicationEventPublisher {

    private Object latestEvent;

    @Override
    public void publishEvent(@Nonnull final Object event) {
      this.latestEvent = event;
    }

    public Object getLatestEvent() {
      return this.latestEvent;
    }
  }
}
