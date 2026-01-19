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
package se.swedenconnect.security.credential.opensaml;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.metadata.EncryptionMethod;
import org.opensaml.xmlsec.encryption.KeySize;
import org.opensaml.xmlsec.encryption.OAEPparams;
import org.opensaml.xmlsec.signature.DigestMethod;

import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

/**
 * Settings for representing {@code md:EncryptionMethod} elements.
 * <p>
 * When represented in properties files as the value for the {@link OpenSamlMetadataProperties#ENCRYPTION_METHODS}
 * metadata property, a string format according to the following format is used:
 * </p>
 * <pre>{@code
 * <encryption-algorithm-uri>[;key-size=<size-in-bits>][;oaep-params=<base64-params>][;digest-method=<digest-method-uri>]}
 * </pre>
 * <p>Example:</p>
 * <pre>{@code
 * <md:EncryptionMethod xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p">
 *   <ds:DigestMethod xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
 * </md:EncryptionMethod>
 *
 * "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p;digest-method=http://www.w3.org/2000/09/xmldsig#sha1"}
 * </pre>
 *
 * @author Martin Lindström
 */
public class EncryptionMethodMetadata {

  public static final String KEY_SIZE_PREFIX = "key-size=";
  public static final String OAEP_PARAMS_PREFIX = "oaep-params=";
  public static final String DIGEST_METHOD_PREFIX = "digest-method=";

  /** The algorithm URI of the encryption method. */
  private String algorithm;

  /** The key size. */
  private Integer keySize;

  /** The OAEP parameters (in Base64-encoding). */
  private String oaepParams;

  /**
   * If {@code algorithm} indicates a key transport algorithm where the digest algorithm needs to be given, this field
   * should be set to this algorithm URI.
   */
  private String digestMethod;

  /**
   * Gets the algorithm URI for the encryption method.
   *
   * @return the algorithm URI for the encryption method
   */
  @Nonnull
  public String getAlgorithm() {
    return this.algorithm;
  }

  /**
   * Assigns the algorithm URI for the encryption method.
   *
   * @param algorithm the algorithm URI
   */
  public void setAlgorithm(@Nonnull final String algorithm) {
    this.algorithm = Objects.requireNonNull(algorithm, "algorithm must not be null");
  }

  /**
   * Gets the key size (relevant if the encryption method is a symmetric algorithm).
   *
   * @return the key size in bits, or {@code null}
   */
  @Nullable
  public Integer getKeySize() {
    return this.keySize;
  }

  /**
   * Assigns the key size.
   *
   * @param keySize the key size in bits
   */
  public void setKeySize(@Nullable final Integer keySize) {
    this.keySize = keySize;
  }

  /**
   * Gets the OAEP parameters (base64-encoded).
   *
   * @return the OAEP parameters or {@code null}
   */
  @Nullable
  public String getOaepParams() {
    return this.oaepParams;
  }

  /**
   * Assigns the OAEP parameters (base64-encoded).
   *
   * @param oaepParams the OAEP parameters
   */
  public void setOaepParams(@Nullable final String oaepParams) {
    this.oaepParams = oaepParams;
  }

  /**
   * Gets the digest algorithm to use. Relevant if the encryption method is
   * {@code http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p} or {@code http://www.w3.org/2009/xmlenc11#rsa-oaep}.
   *
   * @return the digest method, or {@code null}
   */
  @Nullable
  public String getDigestMethod() {
    return this.digestMethod;
  }

  /**
   * Assigns the digest algorithm to use. Relevant if the encryption method is
   * {@code http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p} or {@code http://www.w3.org/2009/xmlenc11#rsa-oaep}.
   *
   * @param digestMethod the digest method
   */
  public void setDigestMethod(@Nullable final String digestMethod) {
    this.digestMethod = digestMethod;
  }

  /**
   * Parses the string representation of an encryption method (see
   * {@link EncryptionMethodMetadata class documentation above}) into an {@link EncryptionMethodMetadata} object.
   *
   * @param method the string representation
   * @return an {@link EncryptionMethodMetadata} object
   * @throws IllegalArgumentException for invalid indata
   */
  @Nonnull
  public static EncryptionMethodMetadata parseMethod(@Nonnull final String method) throws IllegalArgumentException {
    final String[] parts = Objects.requireNonNull(method, "methods must not be null").trim().split(";");
    final EncryptionMethodMetadata emm = new EncryptionMethodMetadata();
    emm.setAlgorithm(parts[0]);
    for (int i = 1; i < parts.length; i++) {
      final String val = parts[i].trim();
      if (val.startsWith(KEY_SIZE_PREFIX)) {
        emm.setKeySize(Integer.parseInt(val.substring(KEY_SIZE_PREFIX.length()).trim()));
      }
      else if (val.startsWith(OAEP_PARAMS_PREFIX)) {
        emm.setOaepParams(val.substring(OAEP_PARAMS_PREFIX.length()).trim());
      }
      else if (val.startsWith(DIGEST_METHOD_PREFIX)) {
        emm.setDigestMethod(val.substring(DIGEST_METHOD_PREFIX.length()).trim());
      }
    }
    return emm;
  }

  /**
   * Parses a string representation of several encryption methods. Each method is separated by a ','. See
   * {@link #parseMethod(String)}.
   *
   * @param methods the string representation
   * @return a list of {@link EncryptionMethodMetadata} objects
   * @throws IllegalArgumentException for invalid indate
   */
  @Nonnull
  public static List<EncryptionMethodMetadata> parseMethods(@Nonnull final String methods)
      throws IllegalArgumentException {
    final String[] m = Objects.requireNonNull(methods, "methods must not be null").trim().split(",");
    return Stream.of(m).map(EncryptionMethodMetadata::parseMethod).toList();
  }

  /**
   * Creates an OpenSAML {@link EncryptionMethod} object given the settings of this object.
   *
   * @return an OpenSAML {@link EncryptionMethod} object
   */
  @Nonnull
  public EncryptionMethod toEncryptionMethod() {
    final EncryptionMethod method =
        (EncryptionMethod) XMLObjectSupport.buildXMLObject(EncryptionMethod.DEFAULT_ELEMENT_NAME);
    method.setAlgorithm(this.algorithm);
    if (this.keySize != null) {
      final KeySize size = (KeySize) XMLObjectSupport.buildXMLObject(KeySize.DEFAULT_ELEMENT_NAME);
      size.setValue(this.keySize);
      method.setKeySize(size);
    }
    if (this.oaepParams != null) {
      final OAEPparams p = (OAEPparams) XMLObjectSupport.buildXMLObject(OAEPparams.DEFAULT_ELEMENT_NAME);
      p.setValue(this.oaepParams);
      method.setOAEPparams(p);
    }
    if (this.digestMethod != null) {
      final DigestMethod dm = (DigestMethod) XMLObjectSupport.buildXMLObject(DigestMethod.DEFAULT_ELEMENT_NAME);
      dm.setAlgorithm(this.digestMethod);
      method.getUnknownXMLObjects().add(dm);
    }
    return method;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder(this.algorithm);
    if (this.keySize != null) {
      sb.append(";").append(KEY_SIZE_PREFIX).append(this.keySize);
    }
    if (this.oaepParams != null) {
      sb.append(";").append(OAEP_PARAMS_PREFIX).append(this.oaepParams);
    }
    if (this.digestMethod != null) {
      sb.append(";").append(DIGEST_METHOD_PREFIX).append(this.digestMethod);
    }
    return sb.toString();
  }
}
