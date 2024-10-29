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
package se.swedenconnect.security.credential.spring;

import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Consumer;

import se.swedenconnect.security.credential.ReloadablePkiCredential;

/**
 * Callback functions for the Spring context test.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class TestMonitorCallbacks {
/*
  public static BiFunction<ReloadablePkiCredential, Exception, Boolean> TEST_FAILURE_CALLBACK = (c, e) -> {
    System.out.println("Test of credential " + c.getName() + " failed with exception: " + e.getClass().getSimpleName());
    return true;
  };

  public static Consumer<ReloadablePkiCredential> RELOAD_SUCCESS_CALLBACK =
      (c) -> System.out.println("Credential " + c.getName() + " was reloaded");

  public static BiConsumer<ReloadablePkiCredential, Exception> RELOAD_FAILURE_CALLBACK = (c, e) ->
  System.out.println("Reloading of credential " + c.getName() + " failed with exception: " + e.getClass().getSimpleName());

  private TestMonitorCallbacks() {
  }

 */
}
