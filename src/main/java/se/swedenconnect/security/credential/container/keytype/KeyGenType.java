package se.swedenconnect.security.credential.container.keytype;

import se.swedenconnect.security.credential.container.keytype.impl.EcKeyGeneratorInitiator;
import se.swedenconnect.security.credential.container.keytype.impl.RsaKeyGeneratorInitiator;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class KeyGenType {

  // Default HSM key type IDs

  public static String RSA_2048 = "RSA-2048";
  public static String RSA_3072 = "RSA-3072";
  public static String RSA_4096 = "RSA-4096";
  public static String EC_P192 = "EC-192";
  public static String EC_P224 = "EC-224";
  public static String EC_P256 = "EC-256";
  public static String EC_P384 = "EC-384";
  public static String EC_P521 = "EC-521";
  public static String EC_BRAINPOOL_192 = "EC-BP-192";
  public static String EC_BRAINPOOL_224 = "EC-BP-224";
  public static String EC_BRAINPOOL_256 = "EC-BP-256";
  public static String EC_BRAINPOOL_320 = "EC-BP-320";
  public static String EC_BRAINPOOL_384 = "EC-BP-384";
  public static String EC_BRAINPOOL_512 = "EC-BP-512";

  // Default HSM Key generator initiators

  public static KeyGeneratorInitiator RSA_2048_Initiator = new RsaKeyGeneratorInitiator(RSA_2048, 2048);
  public static KeyGeneratorInitiator RSA_3072_Initiator = new RsaKeyGeneratorInitiator(RSA_3072, 3072);
  public static KeyGeneratorInitiator RSA_4096_Initiator = new RsaKeyGeneratorInitiator(RSA_4096, 4096);
  public static KeyGeneratorInitiator EC_P192_Initiator = new EcKeyGeneratorInitiator(EC_P192, ECParameterSpecs.NIST_P192);
  public static KeyGeneratorInitiator EC_P224_Initiator = new EcKeyGeneratorInitiator(EC_P224, ECParameterSpecs.NIST_P224);
  public static KeyGeneratorInitiator EC_P256_Initiator = new EcKeyGeneratorInitiator(EC_P256, ECParameterSpecs.NIST_P256);
  public static KeyGeneratorInitiator EC_P384_Initiator = new EcKeyGeneratorInitiator(EC_P384, ECParameterSpecs.NIST_P384);
  public static KeyGeneratorInitiator EC_P521_Initiator = new EcKeyGeneratorInitiator(EC_P521, ECParameterSpecs.NIST_P521);
  public static KeyGeneratorInitiator EC_BRAINPOOL_192_Initiator = new EcKeyGeneratorInitiator(EC_BRAINPOOL_192, ECParameterSpecs.BRAINPOOL_P192R1);
  public static KeyGeneratorInitiator EC_BRAINPOOL_224_Initiator = new EcKeyGeneratorInitiator(EC_BRAINPOOL_224, ECParameterSpecs.BRAINPOOL_P224R1);
  public static KeyGeneratorInitiator EC_BRAINPOOL_256_Initiator = new EcKeyGeneratorInitiator(EC_BRAINPOOL_256, ECParameterSpecs.BRAINPOOL_P256R1);
  public static KeyGeneratorInitiator EC_BRAINPOOL_320_Initiator = new EcKeyGeneratorInitiator(EC_BRAINPOOL_320, ECParameterSpecs.BRAINPOOL_P320R1);
  public static KeyGeneratorInitiator EC_BRAINPOOL_384_Initiator = new EcKeyGeneratorInitiator(EC_BRAINPOOL_384, ECParameterSpecs.BRAINPOOL_P384R1);
  public static KeyGeneratorInitiator EC_BRAINPOOL_512_Initiator = new EcKeyGeneratorInitiator(EC_BRAINPOOL_512, ECParameterSpecs.BRAINPOOL_P512R1);

}
