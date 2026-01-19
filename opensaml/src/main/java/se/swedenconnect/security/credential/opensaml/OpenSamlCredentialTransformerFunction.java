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
package se.swedenconnect.security.credential.opensaml;

import jakarta.annotation.Nonnull;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.X509Credential;
import se.swedenconnect.security.credential.PkiCredential;

import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;

/**
 * Function that transform a {@link PkiCredential} into an OpenSAML {@link X509Credential}.
 *
 * @author Martin Lindström
 */
public class OpenSamlCredentialTransformerFunction implements Function<PkiCredential, X509Credential> {

  /** Accesses the {@code entity-id} metadata property from the supplied credential. */
  public static final Function<PkiCredential, String> defaultEntityIdFunction = c ->
      OpenSamlMetadataProperties.getEntityId(c.getMetadata());

  /** Determines the credential usage. */
  public static final Function<PkiCredential, UsageType> defaultUsageTypeFunction = c ->
      Optional.ofNullable(c.getMetadata().getUsage())
          .map(u -> PkiCredential.Metadata.USAGE_SIGNING.equalsIgnoreCase(u)
              ? UsageType.SIGNING
              : PkiCredential.Metadata.USAGE_ENCRYPTION.equalsIgnoreCase(u)
                  ? UsageType.ENCRYPTION : null)
          .orElse(null);

  /** Function for getting the entityID to assign to the OpenSAML credential. */
  private Function<PkiCredential, String> entityIdFunction = defaultEntityIdFunction;

  /** Function for getting the usage for the credential. */
  private Function<PkiCredential, UsageType> usageTypeFunction = defaultUsageTypeFunction;

  /**
   * Constructor.
   */
  public OpenSamlCredentialTransformerFunction() {
  }

  /**
   * Creates a {@link OpenSamlCredentialTransformerFunction}.
   *
   * @return a a {@link OpenSamlCredentialTransformerFunction}
   */
  @Nonnull
  public static OpenSamlCredentialTransformerFunction function() {
    return new OpenSamlCredentialTransformerFunction();
  }

  /**
   * Transforms the supplied {@link PkiCredential} into an {@link X509Credential}.
   */
  @Override
  @Nonnull
  public X509Credential apply(@Nonnull final PkiCredential credential) {
    final OpenSamlCredential openSamlCredential = new OpenSamlCredential(credential);
    Optional.ofNullable(this.entityIdFunction.apply(credential))
        .ifPresent(openSamlCredential::setEntityId);
    Optional.ofNullable(this.usageTypeFunction.apply(credential))
        .ifPresent(openSamlCredential::setUsageType);

    return openSamlCredential;
  }

  /**
   * Customizes this function with a function that gets the entityID for the credential.
   * <p>
   * The default implementation is the {@link #defaultEntityIdFunction}.
   * </p>
   *
   * @param entityIdFunction the function
   * @return this instance
   */
  @Nonnull
  public OpenSamlCredentialTransformerFunction withEntityIdFunction(
      @Nonnull final Function<PkiCredential, String> entityIdFunction) {
    this.entityIdFunction = Objects.requireNonNull(entityIdFunction, "entityIdFunction must not be null");
    return this;
  }

  /**
   * Assigns the function that gets the SAML entity ID to add to the OpenSAML credential.
   * <p>
   * The default implementation is the {@link #defaultEntityIdFunction}.
   * </p>
   *
   * @param entityIdFunction the function
   * @deprecated use {@link #withEntityIdFunction(Function)} instead
   */
  @Deprecated(since = "2.1.0", forRemoval = true)
  public void setEntityIdFunction(@Nonnull final Function<PkiCredential, String> entityIdFunction) {
    this.entityIdFunction = Objects.requireNonNull(entityIdFunction, "entityIdFunction must not be null");
  }

  /**
   * Customizes this function with a function the gets the credential usage type.
   * <p>
   * The default implementation is the {@link #defaultUsageTypeFunction}.
   * </p>
   *
   * @param usageTypeFunction the function
   * @return this instance
   */
  @Nonnull
  public OpenSamlCredentialTransformerFunction withUsageTypeFunction(
      @Nonnull final Function<PkiCredential, UsageType> usageTypeFunction) {
    this.usageTypeFunction = Objects.requireNonNull(usageTypeFunction, "usageTypeFunction must not be null");
    return this;
  }

}
