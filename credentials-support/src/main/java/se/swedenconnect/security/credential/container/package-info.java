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

/**
 * Support for credential containers.
 *
 * <p>
 * Credential containers are mainly provided to support the use of HSM slots for generating and managing public and
 * private key pairs. But even though HSM slots are the primary use-case, this implementation also fully supports
 * credential containers where the keys are stored on disk or in memory using key stores
 * </p>
 */
package se.swedenconnect.security.credential.container;
