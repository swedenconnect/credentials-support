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
package se.swedenconnect.security.credential.pkcs11;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.util.Objects;
import java.util.Optional;

/**
 * A {@link Pkcs11Configuration} where a PKCS#11 each configuration setting is supplied.
 * <p>
 * Note: This implementation assumes that the SunPKCS11 security provider is used, or other security providers that
 * supports the {@link java.security.KeyStoreSpi}. See {@link AbstractSunPkcs11Configuration}.
 * </p>
 * <p>
 * See <a href="https://docs.oracle.com/en/java/javase/21/security/pkcs11-reference-guide1.html">PKCS#11 Reference
 * Guide</a>.
 * </p>
 *
 * @author Martin Lindström
 */
public class CustomPkcs11Configuration extends AbstractSunPkcs11Configuration {

  /** The PKCS#11 library path. */
  private final String library;

  /** The name of the HSM slot. */
  private final String name;

  /** The slot number/id to use. */
  private final String slot;

  /** The slot index to use. */
  private final Integer slotListIndex;

  /**
   * Constructor setting the library, name, slot and slotListIndex individually.
   * <p>
   * The {@code baseProviderName} is the name of the security provider that we use to create new instances that have
   * names according to {@code <base-provider-name>-<instance-name>}, where 'instance-name' is gotten from the
   * configuration. Implementations wishing to use another provider than "SunPKCS11" should supply this provider name.
   * </p>
   *
   * @param library the PKCS#11 library path
   * @param name the name of the HSM slot
   * @param slot the slot number/id (may be {@code null})
   * @param slotListIndex the slot index (may be {@code null})
   * @param baseProviderName the base provider name (if not given, SunPKCS11 is assumed)
   */
  public CustomPkcs11Configuration(@Nonnull final String library, @Nonnull final String name,
      @Nullable final String slot, @Nullable final Integer slotListIndex, @Nullable final String baseProviderName) {
    super(baseProviderName);
    this.library = Objects.requireNonNull(library, "library must not be null").trim();
    if (this.library.isEmpty()) {
      throw new IllegalArgumentException("library must be assigned");
    }
    this.name = Objects.requireNonNull(name, "name must assigned").trim();
    if (this.name.isEmpty()) {
      throw new IllegalArgumentException("name must be assigned");
    }
    this.slot = Optional.ofNullable(slot).map(String::trim).orElse(null);
    this.slotListIndex = slotListIndex != null
        ? Optional.of(slotListIndex)
        .filter(si -> si >= 0)
        .orElseThrow(() -> new IllegalArgumentException("slotListIndex must be 0 or greater"))
        : null;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected String getConfigurationData() {
    // Manual configuration ...
    // See https://stackoverflow.com/questions/46521791/sunpkcs11-provider-in-java-9.
    //
    final StringBuilder sb = new StringBuilder("--");
    sb.append("library = ").append(this.library).append(System.lineSeparator());
    sb.append("name = ").append(this.name).append(System.lineSeparator());

    if (this.slot != null) {
      sb.append("slot = ").append(this.slot).append(System.lineSeparator());
    }
    if (this.slotListIndex != null) {
      sb.append("slotListIndex = ").append(this.slotListIndex).append(System.lineSeparator());
    }

    return sb.toString();
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return "%s, library='%s', name='%s', slot='%s', slotListIndex='%s'".formatted(
        super.toString(), this.library, this.name, Optional.ofNullable(this.slot).orElse("-"),
        Optional.ofNullable(this.slotListIndex).map(Object::toString).orElse("-"));
  }

}
