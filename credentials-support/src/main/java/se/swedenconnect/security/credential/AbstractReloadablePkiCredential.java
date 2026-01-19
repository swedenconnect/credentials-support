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
package se.swedenconnect.security.credential;

import jakarta.annotation.Nullable;

import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Abstract base class for reloadable credentials.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public abstract class AbstractReloadablePkiCredential extends AbstractPkiCredential implements ReloadablePkiCredential {

  /** The test function for this credential. */
  private Function<ReloadablePkiCredential, Exception> testFunction;

  /**
   * Default constructor.
   */
  public AbstractReloadablePkiCredential() {
    super();
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public Supplier<Exception> getTestFunction() {
    if (this.testFunction != null) {
      return () -> this.testFunction.apply(this);
    }
    else {
      return null;
    }
  }

  /**
   * Assigns a test function for this credential.
   *
   * @param testFunction the function
   */
  public void setTestFunction(@Nullable final Function<ReloadablePkiCredential, Exception> testFunction) {
    this.testFunction = testFunction;
  }

}
