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
package se.swedenconnect.security.credential.container.keytype;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

/**
 * Various parameter specs for elliptic curves. Note that the Brainpool parameter specs are defined by paramters rather
 * than by name in order to support usage with Java PKCS#11 and generation inside HSM.
 * <p>
 * When used like this, the key still appears as named curve.
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ECParameterSpecs {

  /** Algorithm parameter spec Nist P-192 curve. */
  public static final AlgorithmParameterSpec APS_NIST_P192 = new ECGenParameterSpec("secp192r1");

  /** Algorithm parameter spec Nist P-224 curve. */
  public static final AlgorithmParameterSpec APS_NIST_P224 = new ECGenParameterSpec("secp224r1");

  /** Algorithm parameter spec Nist P-256 curve. */
  public static final AlgorithmParameterSpec APS_NIST_P256 = new ECGenParameterSpec("secp256r1");

  /** Algorithm parameter spec Nist P-384 curve. */
  public static final AlgorithmParameterSpec APS_NIST_P384 = new ECGenParameterSpec("secp384r1");

  /** Algorithm parameter spec Nist P-512 curve. */
  public static final AlgorithmParameterSpec APS_NIST_P521 = new ECGenParameterSpec("secp521r1");

  /** Algorithm parameter spec Brainpool P-192 R1 curve. */
  public static final AlgorithmParameterSpec APS_BRAINPOOL_P192R1 = new ECGenParameterSpec("brainpoolp192r1");

  /** Algorithm parameter spec Brainpool P-224 R1 curve. */
  public static final AlgorithmParameterSpec APS_BRAINPOOL_P224R1 = new ECGenParameterSpec("brainpoolp224r1");

  /** Algorithm parameter spec Brainpool P-256 R1 curve. */
  public static final AlgorithmParameterSpec APS_BRAINPOOL_P256R1 = new ECGenParameterSpec("brainpoolp256r1");

  /** Algorithm parameter spec Brainpool P-320 R1 curve. */
  public static final AlgorithmParameterSpec APS_BRAINPOOL_P320R1 = new ECGenParameterSpec("brainpoolp320r1");

  /** Algorithm parameter spec Brainpool P-384 R1 curve. */
  public static final AlgorithmParameterSpec APS_BRAINPOOL_P384R1 = new ECGenParameterSpec("brainpoolp384r1");

  /** Algorithm parameter spec Brainpool P-512 R1 curve. */
  public static final AlgorithmParameterSpec APS_BRAINPOOL_P512R1 = new ECGenParameterSpec("brainpoolp512r1");

  /** Parameter spec Brainpool P192R1. */
  public static final ECParameterSpec SPEC_BRAINPOOL_P192R1 =
      createSpec("C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297",
          "6A91174076B1E0E19C39C031FE8685C1CAE040E5C69A28EF",
          "469A28EF7C28CCA3DC721D044F4496BCCA7EF4146FBF25C9",
          "C0A0647EAAB6A48753B033C56CB0F0900A2F5C4853375FD6",
          "14B690866ABD5BB88B5F4828C1490002E6773FA2FA299B8F",
          "C302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1");

  /** Parameter spec Brainpool P224 R1. */
  public static final ECParameterSpec SPEC_BRAINPOOL_P224R1 =
      createSpec("D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF",
          "68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43",
          "2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B",
          "0D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D",
          "58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD",
          "D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F");

  /** Parameter spec Brainpool P256 R1. */
  public static final ECParameterSpec SPEC_BRAINPOOL_P256R1 =
      createSpec("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
          "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9",
          "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6",
          "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262",
          "547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997",
          "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7");

  /** Parameter spec Brainpool P320 R1. */
  public static final ECParameterSpec SPEC_BRAINPOOL_P320R1 =
      createSpec("D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27",
          "3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4",
          "520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6",
          "43BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E20611",
          "14FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1",
          "D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311");

  /** Parameter spec Brainpool P384 R1. */
  public static final ECParameterSpec SPEC_BRAINPOOL_P384R1 =
      createSpec("8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53",
          "7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826",
          "04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11",
          "1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E",
          "8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315",
          "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565");

  /** Parameter spec Brainpool P512 R1. */
  public static final ECParameterSpec SPEC_BRAINPOOL_P512R1 = createSpec(
      "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3",
      "7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA",
      "3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723",
      "81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822",
      "7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892",
      "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069");

  private static ECParameterSpec createSpec(
      final String prime, final String a, final String b, final String x, final String y, final String n) {
    final ECFieldFp field = new ECFieldFp(new BigInteger(prime, 16));
    final EllipticCurve curve = new EllipticCurve(field, bigIntfromHex(a), bigIntfromHex(b));
    final ECPoint point = new ECPoint(bigIntfromHex(x), bigIntfromHex(y));
    return new ECParameterSpec(curve, point, bigIntfromHex(n), 1);
  }

  private static BigInteger bigIntfromHex(final String hexString) {
    return new BigInteger(hexString, 16);
  }

  // Hidden constructor
  private ECParameterSpecs() {
  }

}
