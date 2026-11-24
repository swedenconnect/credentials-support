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
package se.swedenconnect.security.credential.nimbus;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.PkiCredentialCollection;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Predicate;

/**
 * Wraps a {@link PkiCredentialCollection} and offers JWK Sets for publishing the keys of the collection, and signing
 * of JWTs using the signing credential of the collection.
 * <p>
 * The JWS algorithm for a credential is given by the {@value JwkMetadataProperties#JOSE_ALGORITHM_PROPERTY} metadata
 * property. If this is not set, the algorithm is given by the key type: {@code RS256} for RSA, and the {@code ES}
 * algorithm of the curve for EC.
 * </p>
 *
 * @author Martin Lindström
 */
public class JwkCredentialCollection {

  /** The wrapped collection. */
  private final PkiCredentialCollection collection;

  /** The function that creates JWKs from credentials. */
  private final JwkTransformerFunction jwkFunction;

  /**
   * Constructor using {@link JwkTransformerFunction#publicJwkFunction()} for creating JWKs.
   *
   * @param collection the collection to wrap
   */
  public JwkCredentialCollection(@Nonnull final PkiCredentialCollection collection) {
    this(collection, JwkTransformerFunction.publicJwkFunction());
  }

  /**
   * Constructor.
   *
   * @param collection the collection to wrap
   * @param jwkFunction the function that creates JWKs from credentials (only the public part of the JWKs is used)
   */
  public JwkCredentialCollection(
      @Nonnull final PkiCredentialCollection collection, @Nonnull final JwkTransformerFunction jwkFunction) {
    this.collection = Objects.requireNonNull(collection, "collection must not be null");
    this.jwkFunction = Objects.requireNonNull(jwkFunction, "jwkFunction must not be null");
  }

  /**
   * Gets the wrapped collection.
   *
   * @return the {@link PkiCredentialCollection}
   */
  @Nonnull
  public PkiCredentialCollection getCollection() {
    return this.collection;
  }

  /**
   * Gets the JWK Set to publish, holding the public JWKs of the credentials that are active or not yet active. See
   * {@link PkiCredentialCollection#getCredentialsToPublish()}.
   *
   * @return a {@link JWKSet}
   */
  @Nonnull
  public JWKSet getJwkSet() {
    return this.toJwkSet(this.collection.getCredentialsToPublish());
  }

  /**
   * Gets the JWK Set holding the public JWKs of the credentials that are no longer active, including revoked
   * credentials. See {@link PkiCredentialCollection#getNoLongerActiveCredentials()}.
   *
   * @return a {@link JWKSet}
   */
  @Nonnull
  public JWKSet getNoLongerActiveJwkSet() {
    return this.toJwkSet(this.collection.getNoLongerActiveCredentials());
  }

  /**
   * Signs the supplied claims using the signing credential of the collection. See
   * {@link PkiCredentialCollection#getCredentialForSigning(Predicate)}.
   *
   * @param claims the JWT claims
   * @param type the JWS {@code typ} header parameter, or {@code null}
   * @return a signed JWT
   * @throws JOSEException if no signing credential is found, or for signing errors
   */
  @Nonnull
  public SignedJWT sign(@Nonnull final JWTClaimsSet claims, @Nullable final JOSEObjectType type)
      throws JOSEException {
    return this.sign(claims, type, null, null);
  }

  /**
   * Signs the supplied claims using the signing credential of the collection that supports one of the allowed
   * algorithms. If several of the allowed algorithms can be used with the credential, the first one in the list is
   * used.
   *
   * @param claims the JWT claims
   * @param type the JWS {@code typ} header parameter, or {@code null}
   * @param allowedAlgorithms the allowed algorithms, in order of preference
   * @return a signed JWT
   * @throws JOSEException if no signing credential is found, or for signing errors
   */
  @Nonnull
  public SignedJWT sign(@Nonnull final JWTClaimsSet claims, @Nullable final JOSEObjectType type,
      @Nonnull final List<JWSAlgorithm> allowedAlgorithms) throws JOSEException {
    return this.sign(claims, type, Objects.requireNonNull(allowedAlgorithms, "allowedAlgorithms must not be null"),
        null);
  }

  /**
   * Signs the supplied claims using the signing credential of the collection, and lets the caller add JWS header
   * parameters. The {@code alg} and {@code kid} header parameters are set by this method, also if the customizer sets
   * them.
   *
   * @param claims the JWT claims
   * @param type the JWS {@code typ} header parameter, or {@code null}
   * @param allowedAlgorithms the allowed algorithms, in order of preference, or {@code null} for no restriction
   * @param headerCustomizer a customizer for the JWS header, or {@code null}
   * @return a signed JWT
   * @throws JOSEException if no signing credential is found, or for signing errors
   */
  @Nonnull
  public SignedJWT sign(@Nonnull final JWTClaimsSet claims, @Nullable final JOSEObjectType type,
      @Nullable final List<JWSAlgorithm> allowedAlgorithms, @Nullable final Consumer<JWSHeader.Builder> headerCustomizer)
      throws JOSEException {

    Objects.requireNonNull(claims, "claims must not be null");

    final PkiCredential credential;
    final JWSAlgorithm algorithm;
    if (allowedAlgorithms == null) {
      credential = this.collection.getCredentialForSigning(c -> getAlgorithm(c) != null);
      algorithm = credential != null ? getAlgorithm(credential) : null;
    }
    else {
      credential = this.collection.getCredentialForSigning(
          c -> allowedAlgorithms.stream().anyMatch(a -> supportsAlgorithm(a).test(c)));
      algorithm = credential != null
          ? allowedAlgorithms.stream().filter(a -> supportsAlgorithm(a).test(credential)).findFirst().orElse(null)
          : null;
    }
    if (credential == null || algorithm == null) {
      throw new JOSEException(allowedAlgorithms == null
          ? "No signing credential found"
          : "No signing credential found for algorithms " + allowedAlgorithms);
    }

    final String keyId = credential.transform(this.jwkFunction).getKeyID();
    final JWSHeader.Builder headerBuilder = new JWSHeader.Builder(algorithm).type(type);
    if (headerCustomizer != null) {
      headerCustomizer.accept(headerBuilder);
    }
    headerBuilder.keyID(keyId);

    final SignedJWT jwt = new SignedJWT(headerBuilder.build(), claims);
    jwt.sign(createSigner(credential));
    return jwt;
  }

  /**
   * Returns a {@link Predicate} that tells whether a credential can sign using the given algorithm.
   * <p>
   * If the credential has the {@value JwkMetadataProperties#JOSE_ALGORITHM_PROPERTY} metadata property set, only that
   * algorithm matches. In all cases, the algorithm must fit the key type: an RSA key matches all RSA algorithms
   * ({@code RS} and {@code PS}), and an EC key matches the {@code ES} algorithm of its curve.
   * </p>
   *
   * @param algorithm the algorithm
   * @return a {@link Predicate}
   */
  @Nonnull
  public static Predicate<PkiCredential> supportsAlgorithm(@Nonnull final JWSAlgorithm algorithm) {
    Objects.requireNonNull(algorithm, "algorithm must not be null");
    return c -> {
      final Algorithm joseAlgorithm = JwkMetadataProperties.getJoseAlgorithm(c.getMetadata());
      if (joseAlgorithm != null && !algorithm.getName().equals(joseAlgorithm.getName())) {
        return false;
      }
      return supportsKeyType(algorithm, c.getPublicKey());
    };
  }

  /**
   * Gets the algorithm to use for the credential when no restriction is given.
   *
   * @param credential the credential
   * @return the algorithm, or {@code null} if no algorithm can be determined
   */
  @Nullable
  private static JWSAlgorithm getAlgorithm(@Nonnull final PkiCredential credential) {
    final Algorithm joseAlgorithm = JwkMetadataProperties.getJoseAlgorithm(credential.getMetadata());
    if (joseAlgorithm != null) {
      final JWSAlgorithm jwsAlgorithm = JWSAlgorithm.parse(joseAlgorithm.getName());
      return supportsKeyType(jwsAlgorithm, credential.getPublicKey()) ? jwsAlgorithm : null;
    }
    final PublicKey publicKey = credential.getPublicKey();
    if (publicKey instanceof RSAPublicKey) {
      return JWSAlgorithm.RS256;
    }
    else if (publicKey instanceof final ECPublicKey ecPublicKey) {
      return getEcAlgorithm(ecPublicKey);
    }
    return null;
  }

  /**
   * Tells whether the algorithm can be used with the key type.
   *
   * @param algorithm the algorithm
   * @param publicKey the public key
   * @return {@code true} if the algorithm can be used with the key, and {@code false} otherwise
   */
  private static boolean supportsKeyType(@Nonnull final JWSAlgorithm algorithm, @Nonnull final PublicKey publicKey) {
    if (publicKey instanceof RSAPublicKey) {
      return JWSAlgorithm.Family.RSA.contains(algorithm);
    }
    else if (publicKey instanceof final ECPublicKey ecPublicKey) {
      return algorithm.equals(getEcAlgorithm(ecPublicKey));
    }
    return false;
  }

  /**
   * Gets the {@code ES} algorithm for the curve of an EC key.
   *
   * @param publicKey the EC public key
   * @return the algorithm, or {@code null} if the curve is not supported
   */
  @Nullable
  private static JWSAlgorithm getEcAlgorithm(@Nonnull final ECPublicKey publicKey) {
    final Curve curve = Curve.forECParameterSpec(publicKey.getParams());
    if (Curve.P_256.equals(curve)) {
      return JWSAlgorithm.ES256;
    }
    else if (Curve.P_384.equals(curve)) {
      return JWSAlgorithm.ES384;
    }
    else if (Curve.P_521.equals(curve)) {
      return JWSAlgorithm.ES512;
    }
    else if (Curve.SECP256K1.equals(curve)) {
      return JWSAlgorithm.ES256K;
    }
    return null;
  }

  /**
   * Creates a signer for the credential. The private key is passed as a {@link java.security.PrivateKey}, so that keys
   * on an HSM can be used.
   *
   * @param credential the credential
   * @return a {@link JWSSigner}
   * @throws JOSEException if the signer can not be created
   */
  @Nonnull
  private static JWSSigner createSigner(@Nonnull final PkiCredential credential) throws JOSEException {
    if (credential.getPublicKey() instanceof final ECPublicKey ecPublicKey) {
      return new ECDSASigner(credential.getPrivateKey(), Curve.forECParameterSpec(ecPublicKey.getParams()));
    }
    return new RSASSASigner(credential.getPrivateKey());
  }

  /**
   * Creates a JWK Set holding the public JWKs of the supplied credentials.
   *
   * @param credentials the credentials
   * @return a {@link JWKSet}
   */
  @Nonnull
  private JWKSet toJwkSet(@Nonnull final List<PkiCredential> credentials) {
    return new JWKSet(credentials.stream()
        .map(c -> c.transform(this.jwkFunction))
        .map(JWK::toPublicJWK)
        .toList());
  }

}
