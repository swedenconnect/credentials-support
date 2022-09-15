/*
 * Copyright 2020-2022 Sweden Connect
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
package se.swedenconnect.security.credential.container.keytype;

import se.swedenconnect.security.credential.container.PkiCredentialContainer;

/**
 * Key generation static constants and resources for use with the {@link PkiCredentialContainer} key generation
 * functions.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class KeyGenType {

  /** Key type identifier for RSA 2048 */
  public static final String RSA_2048 = "RSA-2048";

  /** Key type identifier for RSA 3072 */
  public static final String RSA_3072 = "RSA-3072";

  /** Key type identifier for RSA 4096 */
  public static final String RSA_4096 = "RSA-4096";

  /** Key type identifier for elliptic curve keys with curve P-192 */
  public static final String EC_P192 = "EC-192";

  /** Key type identifier for elliptic curve keys with curve P-224 */
  public static final String EC_P224 = "EC-224";

  /** Key type identifier for elliptic curve keys with curve P-256 */
  public static final String EC_P256 = "EC-256";

  /** Key type identifier for elliptic curve keys with curve P-384 */
  public static final String EC_P384 = "EC-384";

  /** Key type identifier for elliptic curve keys with curve P-521 */
  public static final String EC_P521 = "EC-521";

  /** Key type identifier for elliptic curve keys with curve Brainpool P192 R1 */
  public static final String EC_BRAINPOOL_192 = "EC-BP-192";

  /** Key type identifier for elliptic curve keys with curve Brainpool P224 R1 */
  public static final String EC_BRAINPOOL_224 = "EC-BP-224";

  /** Key type identifier for elliptic curve keys with curve Brainpool P256 R1 */
  public static final String EC_BRAINPOOL_256 = "EC-BP-256";

  /** Key type identifier for elliptic curve keys with curve Brainpool P320 R1 */
  public static final String EC_BRAINPOOL_320 = "EC-BP-320";

  /** Key type identifier for elliptic curve keys with curve Brainpool P384 R1 */
  public static final String EC_BRAINPOOL_384 = "EC-BP-384";

  /** Key type identifier for elliptic curve keys with curve Brainpool P512 R1 */
  public static final String EC_BRAINPOOL_512 = "EC-BP-512";

}
