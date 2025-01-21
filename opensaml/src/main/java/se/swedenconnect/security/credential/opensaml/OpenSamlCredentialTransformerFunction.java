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
package se.swedenconnect.security.credential.opensaml;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
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

  /** Function for getting the entityID to assign to the OpenSAML credential. */
  private Function<PkiCredential, String> entityIdFunction = new DefaultEntityIdFunction();

  /**
   * Transforms the supplied {@link PkiCredential} into an {@link X509Credential}.
   */
  @Override
  @Nonnull
  public X509Credential apply(@Nonnull final PkiCredential credential) {
    final OpenSamlCredential openSamlCredential = new OpenSamlCredential(credential);
    openSamlCredential.setEntityId(this.entityIdFunction.apply(credential));
    return openSamlCredential;
  }

  /**
   * Assigns the function that gets the SAML entity ID to add to the OpenSAML credential.
   * <p>
   * The default implementation is the {@link DefaultEntityIdFunction}.
   * </p>
   *
   * @param entityIdFunction the function
   */
  public void setEntityIdFunction(@Nonnull final Function<PkiCredential, String> entityIdFunction) {
    this.entityIdFunction = Objects.requireNonNull(entityIdFunction, "entityIdFunction must not be null");
  }

  /**
   * Default implementation of the function getting the SAML entityID to assign.
   */
  public static final class DefaultEntityIdFunction implements Function<PkiCredential, String> {

    /**
     * Accesses the {@code entity-id} metadata property from the supplied credential.
     */
    @Override
    @Nullable
    public String apply(@Nonnull final PkiCredential credential) {
      return Optional.ofNullable(
              credential.getMetadata().getProperties().get(OpenSamlMetadataProperties.ENTITY_ID_PROPERTY))
          .map(String.class::cast)
          .orElse(null);
    }
  }

}
