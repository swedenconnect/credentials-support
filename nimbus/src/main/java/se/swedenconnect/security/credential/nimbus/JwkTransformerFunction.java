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
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * A function that transforms a {@link PkiCredential} into an {@link JWK}.
 *
 * @author Martin Lindström
 */
public class JwkTransformerFunction implements Function<PkiCredential, JWK> {

  /** KeyID calculation function. */
  private Function<PkiCredential, String> keyIdFunction = new DefaultKeyIdFunction();

  /** Function for the key use property. */
  private Function<PkiCredential, KeyUse> keyUseFunction = new DefaultKeyUseFunction();

  /** Function for the key ops property. */
  private Function<PkiCredential, Set<KeyOperation>> keyOpsFunction = new DefaultKeyOpsFunction();

  /** Function for the alg property. */
  private Function<PkiCredential, Algorithm> algorithmFunction = new DefaultAlgorithmFunction();

  /** For thumbprints. */
  private static final MessageDigest sha256;

  static {
    try {
      sha256 = MessageDigest.getInstance("SHA-256");
    }
    catch (final NoSuchAlgorithmException e) {
      throw new SecurityException(e);
    }
  }

  /**
   * Transforms the supplied {@link PkiCredential} into an {@link JWK}.
   */
  @Override
  public JWK apply(
      @Nonnull final PkiCredential credential) {

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

      jwk = builder
          .keyStore(credential instanceof KeyStoreCredential ? ((KeyStoreCredential) credential).getKeyStore() : null)
          .keyID(this.keyIdFunction.apply(credential))
          .keyUse(this.keyUseFunction.apply(credential))
          .keyOperations(this.keyOpsFunction.apply(credential))
          .algorithm(this.algorithmFunction.apply(credential))
          .x509CertChain(toX5c(credential.getCertificateChain()))
          .x509CertSHA256Thumbprint(toX5t256(credential.getCertificate()))
          .issueTime(Optional.ofNullable(credential.getMetadata().getIssuedAt()).map(Date::from).orElse(null))
          .notBeforeTime(Optional.ofNullable(credential.getMetadata().getIssuedAt()).map(Date::from).orElse(null))
          .expirationTime(Optional.ofNullable(credential.getMetadata().getExpiresAt()).map(Date::from).orElse(null))
          .build();
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

      jwk = builder
          .keyStore(credential instanceof KeyStoreCredential ? ((KeyStoreCredential) credential).getKeyStore() : null)
          .keyID(this.keyIdFunction.apply(credential))
          .keyUse(this.keyUseFunction.apply(credential))
          .keyOperations(this.keyOpsFunction.apply(credential))
          .algorithm(this.algorithmFunction.apply(credential))
          .x509CertChain(toX5c(credential.getCertificateChain()))
          .x509CertSHA256Thumbprint(toX5t256(credential.getCertificate()))
          .issueTime(Optional.ofNullable(credential.getMetadata().getIssuedAt()).map(Date::from).orElse(null))
          .notBeforeTime(Optional.ofNullable(credential.getMetadata().getIssuedAt()).map(Date::from).orElse(null))
          .expirationTime(Optional.ofNullable(credential.getMetadata().getExpiresAt()).map(Date::from).orElse(null))
          .build();
    }
    else {
      throw new IllegalArgumentException("Unsupported key type: " + publicKey.getAlgorithm());
    }

    return jwk;
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

  /**
   * Assigns the function that returns the key ID property (JWK {@code kid} property).
   * <p>
   * The default implementation is {@link DefaultKeyIdFunction}.
   * </p>
   *
   * @param keyIdFunction the function
   */
  public void setKeyIdFunction(@Nonnull final Function<PkiCredential, String> keyIdFunction) {
    this.keyIdFunction = Objects.requireNonNull(keyIdFunction, "keyIdFunction must not be null");
  }

  /**
   * Assigns the function that returns the key use property (JWK {@code use} property).
   * <p>
   * The default implementation is {@link DefaultKeyUseFunction}.
   * </p>
   *
   * @param keyUseFunction the function
   */
  public void setKeyUseFunction(
      @Nonnull final Function<PkiCredential, KeyUse> keyUseFunction) {
    this.keyUseFunction = Objects.requireNonNull(keyUseFunction, "keyUseFunction must not be null");
  }

  /**
   * Assigns the function that returns a set of {@link KeyOperation}s.
   * <p>
   * The default implementation is {@link DefaultKeyOpsFunction}.
   * </p>
   *
   * @param keyOpsFunction the function
   */
  public void setKeyOpsFunction(@Nonnull final Function<PkiCredential, Set<KeyOperation>> keyOpsFunction) {
    this.keyOpsFunction = Objects.requireNonNull(keyOpsFunction, "keyOpsFunction must not be null");
  }

  /**
   * Assigns the function that returns the JOSE algorithm.
   * <p>
   * The default implementation is {@link DefaultAlgorithmFunction}.
   * </p>
   *
   * @param algorithmFunction the function
   */
  public void setAlgorithmFunction(@Nonnull final Function<PkiCredential, Algorithm> algorithmFunction) {
    this.algorithmFunction = Objects.requireNonNull(algorithmFunction, "algorithmFunction must not be null");
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
   * Default implementation of the function that returns the {@link KeyUse} for a credential.
   */
  public static final class DefaultKeyUseFunction implements Function<PkiCredential, KeyUse> {

    /**
     * Will use the {@code key-use} property from the metadata, and if not present, use the certificate to calculate the
     * usage.
     */
    @Override
    @Nullable
    public KeyUse apply(@Nonnull final PkiCredential credential) {
      return Optional.ofNullable(credential.getMetadata().getProperties().get(JwkMetadataProperties.KEY_USE_PROPERTY))
          .map(ku -> {
            if (ku instanceof final KeyUse keyUse) {
              return keyUse;
            }
            else if (ku instanceof final String keyUseString) {
              return new KeyUse(keyUseString);
            }
            else {
              throw new IllegalArgumentException("Unknown key use type: " + ku.getClass().getName());
            }
          })
          .orElseGet(() -> Optional.ofNullable(credential.getCertificate())
              .map(KeyUse::from)
              .orElse(null));
    }
  }

  /**
   * Default implementation of the function that returns a set of {@link KeyOperation}s for a credential.
   */
  public static class DefaultKeyOpsFunction implements Function<PkiCredential, Set<KeyOperation>> {

    /**
     * Returns a {@link Set} of {@link KeyOperation}s if the metadata property {@code key-ops} is assigned to any of the
     * following:
     * <ul>
     * <li>A {@link Collection} of {@link KeyOperation} objects.</li>
     * <li>A single {@link KeyOperation} object.</li>
     * <li>An array of {@link KeyOperation} objects.</li>
     * <li>A comma separated string with key operations (see valid string values in {@link KeyOperation}).</li>
     * </ul>
     */
    @Override
    @Nullable
    public Set<KeyOperation> apply(@Nonnull final PkiCredential credential) {
      final Object metadata = credential.getMetadata().getProperties().get(JwkMetadataProperties.KEY_OPS_PROPERTY);
      if (metadata == null) {
        return null;
      }
      if (metadata instanceof final KeyOperation keyOperation) {
        return Set.of(keyOperation);
      }
      else if (metadata instanceof final KeyOperation[] keyOperations) {
        return new HashSet<>(Arrays.asList(keyOperations));
      }
      else if (metadata instanceof final String keyOpString) {
        try {
          return KeyOperation.parse(Arrays.asList(keyOpString.split(",")));
        }
        catch (final ParseException e) {
          throw new IllegalArgumentException("Invalid key operation set: " + keyOpString, e);
        }
      }
      else if (metadata instanceof final Collection<?> keyOperations) {
        return keyOperations.stream()
            .map(k -> {
              if (k instanceof final KeyOperation keyOperation) {
                return keyOperation;
              }
              else if (k instanceof final String keyOpString) {
                try {
                  return KeyOperation.parse(List.of(keyOpString)).stream().findFirst().orElse(null);
                }
                catch (final ParseException e) {
                  throw new IllegalArgumentException("Invalid key operation: " + keyOpString, e);
                }
              }
              else {
                throw new IllegalArgumentException("Invalid type of key operation: " + k.getClass().getName());
              }
            })
            .filter(Objects::nonNull)
            .collect(Collectors.toSet());
      }
      else {
        throw new IllegalArgumentException("Invalid key operation type: " + metadata.getClass().getName());
      }
    }
  }

  /**
   * Default implementation of the function that returns the JOSE algorithm ({@code alg} property).
   */
  public static final class DefaultAlgorithmFunction implements Function<PkiCredential, Algorithm> {

    /**
     * If the credential metadata property {@code jose-alg} is assigned to an {@link Algorithm} or string, an
     * {@link Algorithm} is returned, otherwise {@code null}.
     */
    @Override
    @Nullable
    public Algorithm apply(@Nonnull final PkiCredential credential) {
      return Optional.ofNullable(credential.getMetadata().getProperties()
              .get(JwkMetadataProperties.JOSE_ALGORITHM_PROPERTY))
          .map(a -> {
            if (a instanceof final Algorithm algorithm) {
              return algorithm;
            }
            else if (a instanceof final String algorithmString) {
              return new Algorithm(algorithmString);
            }
            else {
              throw new IllegalArgumentException("Unknown type for the JOSE algorithm: " + a.getClass().getName());
            }
          })
          .orElse(null);
    }
  }

}
