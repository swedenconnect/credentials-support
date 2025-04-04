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
package se.swedenconnect.security.credential.spring.converters;

import jakarta.annotation.Nonnull;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.core.convert.converter.Converter;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.bundle.CredentialBundles;
import se.swedenconnect.security.credential.spring.config.PkiCredentialReference;

import java.util.Objects;

/**
 * A {@link Converter} that accepts a string that is a reference to a registered {@link PkiCredential} and uses the
 * system {@link CredentialBundles} bean to create a resolvable {@link PkiCredentialReference}.
 *
 * @author Martin Lindström
 */
public class PkiCredentialReferenceConverter implements Converter<String, PkiCredentialReference>,
    ApplicationContextAware {

  /** The application context. */
  private ApplicationContext applicationContext;

  /**
   * Converts a registered credential ID into a {@link PkiCredentialReference} object.
   */
  @Override
  @Nonnull
  public PkiCredentialReference convert(@Nonnull final String source) {
    Objects.requireNonNull(source, "source must not be null");
    return () -> this.applicationContext.getBean(CredentialBundles.class).getCredential(source);
  }

  @Override
  public void setApplicationContext(@Nonnull final ApplicationContext applicationContext) throws BeansException {
    this.applicationContext = applicationContext;
  }

}
