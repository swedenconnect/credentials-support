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
package se.swedenconnect.security.credential.opensaml;

/**
 * Symbolic constants for storing OpenSAML specific properties in a
 * {@link se.swedenconnect.security.credential.PkiCredential.Metadata PkiCredential.Metadata} object.
 *
 * @author Martin Lindström
 */
public class OpenSamlMetadataProperties {

  /**
   * Property name for assigning a SAML entity ID to the credential metadata.
   */
  public static final String ENTITY_ID_PROPERTY = "entity-id";

}
