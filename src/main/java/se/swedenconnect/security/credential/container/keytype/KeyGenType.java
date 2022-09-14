package se.swedenconnect.security.credential.container.keytype;

import se.swedenconnect.security.credential.container.keytype.impl.EcKeyPairGeneratorFactory;
import se.swedenconnect.security.credential.container.keytype.impl.RsaKeyPairGeneratorFactory;

/**
 * Key generation static constants and resources for use with the
 * {@link se.swedenconnect.security.credential.container.PkiCredentialContainer} key generation functions
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class KeyGenType {

  // Default HSM key type IDs

  /** Key type identifier for RSA 2048 */
  public static final String RSA_2048 = "RSA-2048";
  /** Key type identifier for RSA 3072 */
  public static final  String RSA_3072 = "RSA-3072";
  /** Key type identifier for RSA 4096 */
  public static final  String RSA_4096 = "RSA-4096";
  /** Key type identifier for elliptic curve keys with curve P-192 */
  public static final  String EC_P192 = "EC-192";
  /** Key type identifier for elliptic curve keys with curve P-224 */
  public static final  String EC_P224 = "EC-224";
  /** Key type identifier for elliptic curve keys with curve P-256 */
  public static final  String EC_P256 = "EC-256";
  /** Key type identifier for elliptic curve keys with curve P-384 */
  public static final  String EC_P384 = "EC-384";
  /** Key type identifier for elliptic curve keys with curve P-521 */
  public static final  String EC_P521 = "EC-521";
  /** Key type identifier for elliptic curve keys with curve Brainpool P192 R1 */
  public static final  String EC_BRAINPOOL_192 = "EC-BP-192";
  /** Key type identifier for elliptic curve keys with curve Brainpool P224 R1 */
  public static final  String EC_BRAINPOOL_224 = "EC-BP-224";
  /** Key type identifier for elliptic curve keys with curve Brainpool P256 R1 */
  public static final  String EC_BRAINPOOL_256 = "EC-BP-256";
  /** Key type identifier for elliptic curve keys with curve Brainpool P320 R1 */
  public static final  String EC_BRAINPOOL_320 = "EC-BP-320";
  /** Key type identifier for elliptic curve keys with curve Brainpool P384 R1 */
  public static final  String EC_BRAINPOOL_384 = "EC-BP-384";
  /** Key type identifier for elliptic curve keys with curve Brainpool P512 R1 */
  public static final  String EC_BRAINPOOL_512 = "EC-BP-512";

  // Default HSM Key generator initiators

  /**  Key pair generator factory for generating keys of type RSA 2048 */
  public static final KeyPairGeneratorFactory RSA_2048_Factory = new RsaKeyPairGeneratorFactory(RSA_2048, 2048);
  /**  Key pair generator factory for generating keys of type RSA 3072 */
  public static final KeyPairGeneratorFactory RSA_3072_Factory = new RsaKeyPairGeneratorFactory(RSA_3072, 3072);
  /**  Key pair generator factory for generating keys of type RSA  4096 */
  public static final KeyPairGeneratorFactory RSA_4096_Factory = new RsaKeyPairGeneratorFactory(RSA_4096, 4096);
  /**  Key pair generator factory for generating keys of type EC NIST P192 */
  public static final KeyPairGeneratorFactory EC_P192_Factory = new EcKeyPairGeneratorFactory(EC_P192,
    ECParameterSpecs.NIST_P192);
  /**  Key pair generator factory for generating keys of type EC NIST P224 */
  public static final KeyPairGeneratorFactory EC_P224_Factory = new EcKeyPairGeneratorFactory(EC_P224,
    ECParameterSpecs.NIST_P224);
  /**  Key pair generator factory for generating keys of type EC NIST P256 */
  public static final KeyPairGeneratorFactory EC_P256_Factory = new EcKeyPairGeneratorFactory(EC_P256,
    ECParameterSpecs.NIST_P256);
  /**  Key pair generator factory for generating keys of type EC NIST P384 */
  public static final KeyPairGeneratorFactory EC_P384_Factory = new EcKeyPairGeneratorFactory(EC_P384,
    ECParameterSpecs.NIST_P384);
  /**  Key pair generator factory for generating keys of type EC NIST P521 */
  public static final KeyPairGeneratorFactory EC_P521_Factory = new EcKeyPairGeneratorFactory(EC_P521,
    ECParameterSpecs.NIST_P521);
  /**  Key pair generator factory for generating keys of type EC Brainpool P192 R1*/
  public static final KeyPairGeneratorFactory EC_BRAINPOOL_192_Factory = new EcKeyPairGeneratorFactory(EC_BRAINPOOL_192,
    ECParameterSpecs.BRAINPOOL_P192R1);
  /**  Key pair generator factory for generating keys of type EC Brainpool P224 R1*/
  public static final KeyPairGeneratorFactory EC_BRAINPOOL_224_Factory = new EcKeyPairGeneratorFactory(EC_BRAINPOOL_224,
    ECParameterSpecs.BRAINPOOL_P224R1);
  /**  Key pair generator factory for generating keys of type EC Brainpool P256 R1*/
  public static final KeyPairGeneratorFactory EC_BRAINPOOL_256_Factory = new EcKeyPairGeneratorFactory(EC_BRAINPOOL_256,
    ECParameterSpecs.BRAINPOOL_P256R1);
  /**  Key pair generator factory for generating keys of type EC Brainpool P320 R1*/
  public static final KeyPairGeneratorFactory EC_BRAINPOOL_320_Factory = new EcKeyPairGeneratorFactory(EC_BRAINPOOL_320,
    ECParameterSpecs.BRAINPOOL_P320R1);
  /**  Key pair generator factory for generating keys of type EC Brainpool P384 R1*/
  public static final KeyPairGeneratorFactory EC_BRAINPOOL_384_Factory = new EcKeyPairGeneratorFactory(EC_BRAINPOOL_384,
    ECParameterSpecs.BRAINPOOL_P384R1);
  /**  Key pair generator factory for generating keys of type EC Brainpool P512 R1*/
  public static final KeyPairGeneratorFactory EC_BRAINPOOL_512_Factory = new EcKeyPairGeneratorFactory(EC_BRAINPOOL_512,
    ECParameterSpecs.BRAINPOOL_P512R1);

}
