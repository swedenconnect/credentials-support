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
package se.swedenconnect.security.credential.nimbus;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

/**
 * A function that transforms a {@link PkiCredential} into an {@link JWK}.
 *
 * @author Martin Lindström
 */
public class JwkTransformerFunction implements Function<PkiCredential, JWK> {

  /** Default function for getting the key use. Note that if key ops are set, no use is returned. */
  public static final Function<PkiCredential, KeyUse> defaultKeyUseFunction = c -> {
    if (Optional.ofNullable(JwkMetadataProperties.getKeyOps(c.getMetadata()))
        .filter(s -> !s.isEmpty()).isPresent()) {
      return null;
    }
    return JwkMetadataProperties.getKeyUse(c.getMetadata());
  };

  /** Default function for getting the key operation property. */
  public static final Function<PkiCredential, Set<KeyOperation>> defaultKeyOpsFunction =
      c -> JwkMetadataProperties.getKeyOps(c.getMetadata());

  /** Default algorithm for getting the JOSE algorithm. */
  public static final Function<PkiCredential, Algorithm> defaultAlgorithmFunction =
      c -> JwkMetadataProperties.getJoseAlgorithm(c.getMetadata());

  /** KeyID calculation function. */
  private Function<PkiCredential, String> keyIdFunction = new DefaultKeyIdFunction();

  /** Function for the key use property. */
  private Function<PkiCredential, KeyUse> keyUseFunction = defaultKeyUseFunction;

  /** Function for the key ops property. */
  private Function<PkiCredential, Set<KeyOperation>> keyOpsFunction = defaultKeyOpsFunction;

  /** Function for the alg property. */
  private Function<PkiCredential, Algorithm> algorithmFunction = defaultAlgorithmFunction;

  /** For thumbprints. */
  private static final MessageDigest sha256;

  /** Customizers to be applied after defaults */
  private final List<Function<RSAKey.Builder, RSAKey.Builder>> rsaCustomizers = new ArrayList<>();

  /** Customizers to be applied after defaults */
  private final List<Function<ECKey.Builder, ECKey.Builder>> ecCustomizers = new ArrayList<>();

  static {
    try {
      sha256 = MessageDigest.getInstance("SHA-256");
    }
    catch (final NoSuchAlgorithmException e) {
      throw new SecurityException(e);
    }
  }

  /**
   * Constructor.
   */
  public JwkTransformerFunction() {
  }

  /**
   * Creates a {@link JwkTransformerFunction} with default settings.
   *
   * @return a {@link JwkTransformerFunction}
   */
  @Nonnull
  public static JwkTransformerFunction function() {
    return new JwkTransformerFunction();
  }

  /**
   * Transforms the supplied {@link PkiCredential} into an {@link JWK}.
   */
  @Override
  @Nonnull
  public JWK apply(@Nonnull final PkiCredential credential) {

    final JWK jwk;

    final PublicKey publicKey = credential.getPublicKey();

    if (publicKey instanceof final RSAPublicKey rsaPublicKey) {
      final RSAKey.Builder builder = new RSAKey.Builder(rsaPublicKey);

      // Special handling of PKCS#11 keys ...
      if (credential.getPrivateKey() instanceof final RSAPrivateKey rsaPrivateKey) {
        builder.privateKey(rsaPrivateKey);
      }
      else {
        builder.privateKey(credential.getPrivateKey());
      }

      builder
          .keyStore(credential instanceof KeyStoreCredential ? ((KeyStoreCredential) credential).getKeyStore() : null)
          .keyID(this.keyIdFunction.apply(credential))
          .keyUse(this.keyUseFunction.apply(credential))
          .keyOperations(this.keyOpsFunction.apply(credential))
          .algorithm(this.algorithmFunction.apply(credential))
          .x509CertChain(toX5c(credential.getCertificateChain()))
          .x509CertSHA256Thumbprint(toX5t256(credential.getCertificate()))
          .issueTime(Optional.ofNullable(credential.getMetadata().getIssuedAt()).map(Date::from).orElse(null))
          .notBeforeTime(Optional.ofNullable(credential.getMetadata().getIssuedAt()).map(Date::from).orElse(null))
          .expirationTime(Optional.ofNullable(credential.getMetadata().getExpiresAt()).map(Date::from).orElse(null));

      this.rsaCustomizers.forEach(customizer -> customizer.apply(builder));
      jwk = builder.build();
    }
    else if (publicKey instanceof final ECPublicKey ecPublicKey) {
      final Curve curve = Curve.forECParameterSpec(ecPublicKey.getParams());
      if (curve == null) {
        throw new IllegalArgumentException("Could not determine curve");
      }
      final ECKey.Builder builder = new ECKey.Builder(curve, ecPublicKey);

      // Special handling of PKCS#11 keys ...
      if (credential.getPrivateKey() instanceof final ECPrivateKey ecPrivateKey) {
        builder.privateKey(ecPrivateKey);
      }
      else {
        builder.privateKey(credential.getPrivateKey());
      }

      builder
          .keyStore(credential instanceof KeyStoreCredential ? ((KeyStoreCredential) credential).getKeyStore() : null)
          .keyID(this.keyIdFunction.apply(credential))
          .keyUse(this.keyUseFunction.apply(credential))
          .keyOperations(this.keyOpsFunction.apply(credential))
          .algorithm(this.algorithmFunction.apply(credential))
          .x509CertChain(toX5c(credential.getCertificateChain()))
          .x509CertSHA256Thumbprint(toX5t256(credential.getCertificate()))
          .issueTime(Optional.ofNullable(credential.getMetadata().getIssuedAt()).map(Date::from).orElse(null))
          .notBeforeTime(Optional.ofNullable(credential.getMetadata().getIssuedAt()).map(Date::from).orElse(null))
          .expirationTime(Optional.ofNullable(credential.getMetadata().getExpiresAt()).map(Date::from).orElse(null));

      this.ecCustomizers.forEach(customizer -> customizer.apply(builder));

      jwk = builder.build();
    }
    else {
      throw new IllegalArgumentException("Unsupported key type: " + publicKey.getAlgorithm());
    }

    return jwk;
  }

  /**
   * Customizes this function with a generic function that may modify RSA keys.
   *
   * @param customizer to apply after default properties is set for key
   * @return this instance
   */
  @Nonnull
  public JwkTransformerFunction withRsaCustomizer(@Nonnull final Function<RSAKey.Builder, RSAKey.Builder> customizer) {
    this.rsaCustomizers.add(customizer);
    return this;
  }

  /**
   * Customizes this function with a generic function that may modify EC keys.
   *
   * @param customizer to apply after default properties is set for key
   * @return this instance
   */
  @Nonnull
  public JwkTransformerFunction withEcKeyCustomizer(@Nonnull final Function<ECKey.Builder, ECKey.Builder> customizer) {
    this.ecCustomizers.add(customizer);
    return this;
  }

  /**
   * Customizes the function to remove the {@link java.security.KeyStore} of any created
   * {@link com.nimbusds.jose.jwk.JWK} which makes keys unserializable.
   *
   * @return this instance
   */
  @Nonnull
  public JwkTransformerFunction serializable() {
    return this.withRsaCustomizer(b -> b.keyStore(null)).withEcKeyCustomizer(b -> b.keyStore(null));
  }

  /**
   * Customizes the function with a custom function for calculating the key ID property (JWK {@code kid} property).
   * <p>
   * The default implementation is {@link DefaultKeyIdFunction}.
   * </p>
   *
   * @param keyIdFunction the function
   * @return this instance
   */
  @Nonnull
  public JwkTransformerFunction withKeyIdFunction(@Nonnull final Function<PkiCredential, String> keyIdFunction) {
    this.keyIdFunction = Objects.requireNonNull(keyIdFunction, "keyIdFunction must not be null");
    return this;
  }

  /**
   * Assigns the function that returns the key ID property (JWK {@code kid} property).
   * <p>
   * The default implementation is {@link DefaultKeyIdFunction}.
   * </p>
   *
   * @param keyIdFunction the function
   * @deprecated use {@link #withKeyIdFunction(Function)} instead
   */
  @Deprecated(since = "2.1.0", forRemoval = true)
  public void setKeyIdFunction(@Nonnull final Function<PkiCredential, String> keyIdFunction) {
    this.withKeyIdFunction(keyIdFunction);
  }

  /**
   * Customizes this function with a function for getting the key use property (JWK {@code use} property).
   * <p>
   * The default implementation is {@link #defaultKeyUseFunction}.
   * </p>
   *
   * @param keyUseFunction the function
   * @return this instance
   */
  @Nonnull
  public JwkTransformerFunction withKeyUseFunction(@Nonnull final Function<PkiCredential, KeyUse> keyUseFunction) {
    this.keyUseFunction = Objects.requireNonNull(keyUseFunction, "keyUseFunction must not be null");
    return this;
  }

  /**
   * Assigns the function that returns the key use property (JWK {@code use} property).
   * <p>
   * The default implementation is {@link #defaultKeyUseFunction}.
   * </p>
   *
   * @param keyUseFunction the function
   * @deprecated use {@link #withKeyUseFunction(Function)} instead
   */
  @Deprecated(since = "2.1.0", forRemoval = true)
  public void setKeyUseFunction(
      @Nonnull final Function<PkiCredential, KeyUse> keyUseFunction) {
    this.keyUseFunction = Objects.requireNonNull(keyUseFunction, "keyUseFunction must not be null");
  }

  /**
   * Customizes this function with a function that returns a set of {@link KeyOperation}s.
   * <p>
   * The default implementation is {@link #defaultKeyOpsFunction}.
   * </p>
   *
   * @param keyOpsFunction the function
   * @return this instance
   */
  public JwkTransformerFunction withKeyOpsFunction(
      @Nonnull final Function<PkiCredential, Set<KeyOperation>> keyOpsFunction) {
    this.keyOpsFunction = Objects.requireNonNull(keyOpsFunction, "keyOpsFunction must not be null");
    return this;
  }

  /**
   * Assigns the function that returns a set of {@link KeyOperation}s.
   * <p>
   * The default implementation is {@link #defaultKeyOpsFunction}.
   * </p>
   *
   * @param keyOpsFunction the function
   * @deprecated use {@link #withKeyOpsFunction(Function)} instead
   */
  @Deprecated(since = "2.1.0", forRemoval = true)
  public void setKeyOpsFunction(@Nonnull final Function<PkiCredential, Set<KeyOperation>> keyOpsFunction) {
    this.withKeyOpsFunction(keyOpsFunction);
  }

  /**
   * Customizes this function with a function that returns the JOSE algorithm.
   * <p>
   * The default implementation is {@link #defaultAlgorithmFunction}.
   * </p>
   *
   * @param algorithmFunction the function
   * @return this instance
   */
  @Nonnull
  public JwkTransformerFunction withAlgorithmFunction(
      @Nonnull final Function<PkiCredential, Algorithm> algorithmFunction) {
    this.algorithmFunction = Objects.requireNonNull(algorithmFunction, "algorithmFunction must not be null");
    return this;
  }

  /**
   * Assigns the function that returns the JOSE algorithm.
   * <p>
   * The default implementation is {@link #defaultAlgorithmFunction}.
   * </p>
   *
   * @param algorithmFunction the function
   * @deprecated use {@link #withAlgorithmFunction(Function)} instead
   */
  @Deprecated(since = "2.1.0", forRemoval = true)
  public void setAlgorithmFunction(@Nonnull final Function<PkiCredential, Algorithm> algorithmFunction) {
    this.withAlgorithmFunction(algorithmFunction);
  }

  /**
   * Default implementation of the function that returns the key id (JWT {@code kid} property).
   */
  public static class DefaultKeyIdFunction implements Function<PkiCredential, String> {

    /**
     * If the credential metadata contains a {@code key-id}, this is used, otherwise the function attempts to calculate
     * the RFC 7638 thumbprint, and finally the serial number of the certificate is used for key id-calculation.
     */
    @Override
    @Nullable
    public String apply(@Nonnull final PkiCredential credential) {
      return Optional.ofNullable(credential.getMetadata().getKeyId())
          .orElseGet(() -> Optional.ofNullable(this.calculateThumbprint(credential))
              .orElseGet(() -> Optional.ofNullable(credential.getCertificate())
                  .map(c -> c.getSerialNumber().toString(10))
                  .orElse(null)));
    }

    /**
     * Calculates the RFC 7638 thumbprint.
     *
     * @param credential the credential
     * @return the thumbprint
     */
    @Nullable
    private String calculateThumbprint(@Nonnull final PkiCredential credential) {
      try {
        if (credential.getPublicKey() instanceof final RSAPublicKey rsaPublicKey) {
          return new RSAKey.Builder(rsaPublicKey).build().computeThumbprint().toString();
        }
        else if (credential.getPublicKey() instanceof final ECPublicKey ecPublicKey) {
          final Curve curve = Curve.forECParameterSpec(ecPublicKey.getParams());
          return new ECKey.Builder(curve, ecPublicKey).build().computeThumbprint().toString();
        }
        else {
          return null;
        }
      }
      catch (final Exception e) {
        return null;
      }
    }
  }

  /**
   * Converts the certificate chain of a credential into a list of encodings.
   *
   * @param chain the chain (possibly empty)
   * @return a list of Base64 encodings, or {@code null} if no certificates are available
   */
  @Nullable
  private static List<Base64> toX5c(@Nonnull final List<X509Certificate> chain) {
    if (chain.isEmpty()) {
      return null;
    }
    return chain.stream()
        .map(c -> {
          try {
            return Base64.encode(c.getEncoded());
          }
          catch (final CertificateEncodingException e) {
            throw new RuntimeException(e);
          }
        })
        .toList();
  }

  /**
   * Calculates the X.509 certificate SHA-256 thumbprint.
   *
   * @param certificate the certificate (may be {@code null})
   * @return the SHA-256 thumbprint, or {@code null}
   */
  @Nullable
  private static Base64URL toX5t256(@Nonnull final X509Certificate certificate) {
    return Optional.ofNullable(certificate)
        .map(c -> {
          try {
            return Base64URL.encode(sha256.digest(certificate.getEncoded()));
          }
          catch (final CertificateEncodingException e) {
            throw new RuntimeException(e);
          }
        })
        .orElse(null);
  }

}
