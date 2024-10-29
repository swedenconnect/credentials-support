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
package se.swedenconnect.security.credential;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Optional;

/**
 * Abstract base class for classes implementing the {@link PkiCredential} interface.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public abstract class AbstractPkiCredential implements PkiCredential {

  /** The credential name. */
  private String name;

  /**
   * Default constructor.
   */
  public AbstractPkiCredential() {
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public PublicKey getPublicKey() {
    return Optional.ofNullable(this.getCertificate())
        .map(X509Certificate::getPublicKey)
        .orElseGet(() -> Optional.ofNullable(this.getStandalonePublicKey())
            .orElseThrow(() -> new IllegalArgumentException("No public key found")));
  }

  /**
   * If a credential without a certificate is created, this method must be overridden and return the installed
   * {@link PublicKey}.
   *
   * @return the standalone public key, or {@code null} if a certificate is present
   */
  @Nullable
  protected PublicKey getStandalonePublicKey() {
    return null;
  }

  /**
   * Gets the name of the credential. If no name has been explicitly assigned, the default name is used.
   */
  @Override
  @Nonnull
  public String getName() {
    return Optional.ofNullable(this.name).orElseGet(this::getDefaultName);
  }

  /**
   * Assigns the credential name.
   *
   * @param name the name
   */
  public void setName(@Nonnull final String name) {
    this.name = name;
  }

  /**
   * If the credential {@code name} property is not explicitly assigned using {@link #setName(String)} a name is
   * calculated based on a credential's properties.
   *
   * @return the credential name
   */
  @Nonnull
  protected abstract String getDefaultName();

}
