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
package se.swedenconnect.security.credential.spring.monitoring.events;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test cases for events.
 *
 * @author Martin Lindström
 */
class EventsTest {

  @Test
  void testSuccessfulCredentialTestEvent() {
    final SuccessfulCredentialTestEvent event = new SuccessfulCredentialTestEvent("name");

    assertEquals("name", event.getCredentialName());
    assertEquals("name", event.getSource());

    assertThrows(NullPointerException.class, () -> new SuccessfulCredentialTestEvent(null));
  }

  @Test
  void testFailedCredentialTestEvent() {
    final FailedCredentialTestEvent event =
        new FailedCredentialTestEvent("name", "error", Exception.class.getName());
    assertEquals("name", event.getCredentialName());
    assertEquals("name", event.getSource());
    assertThrows(NullPointerException.class,
        () -> new FailedCredentialTestEvent(null, "error", Exception.class.getName()));

    assertEquals("error", event.getError());
    assertThrows(NullPointerException.class,
        () -> new FailedCredentialTestEvent("name", null, Exception.class.getName()));

    assertEquals(Exception.class.getName(), event.getException());
    assertDoesNotThrow(() -> new FailedCredentialTestEvent("name", "error", null));
  }

  @Test
  void testSuccessfulCredentialReloadEvent() {
    final SuccessfulCredentialReloadEvent event = new SuccessfulCredentialReloadEvent("name");

    assertEquals("name", event.getCredentialName());
    assertEquals("name", event.getSource());

    assertThrows(NullPointerException.class, () -> new SuccessfulCredentialReloadEvent(null));
  }

  @Test
  void testFailedCredentialReloadEvent() {
    final FailedCredentialReloadEvent event =
        new FailedCredentialReloadEvent("name", "error", Exception.class.getName());
    assertEquals("name", event.getCredentialName());
    assertEquals("name", event.getSource());
    assertThrows(NullPointerException.class,
        () -> new FailedCredentialReloadEvent(null, "error", Exception.class.getName()));

    assertEquals("error", event.getError());
    assertThrows(NullPointerException.class,
        () -> new FailedCredentialReloadEvent("name", null, Exception.class.getName()));

    assertEquals(Exception.class.getName(), event.getException());
    assertDoesNotThrow(() -> new FailedCredentialReloadEvent("name", "error", null));
  }
}
