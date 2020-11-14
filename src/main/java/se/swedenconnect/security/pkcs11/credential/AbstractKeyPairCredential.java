/*
 * Copyright 2020 Sweden Connect
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
package se.swedenconnect.security.pkcs11.credential;

import java.io.InputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.Optional;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.util.Arrays;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public abstract class AbstractKeyPairCredential implements KeyPairCredential {

  private PublicKey publicKey;

  private PrivateKey privateKey;

  private KeyStore keyStore;

  private String keyStoreAlias;

  private char[] keyStoreKeyPassword;

  private Provider keyStoreProvider;

  private X509Certificate certificate;

  public AbstractKeyPairCredential(final KeyPair keyPair) {
    if (keyPair == null) {
      throw new IllegalArgumentException("keyPair must not be null");
    }
    this.publicKey = Optional.ofNullable(keyPair.getPublic())
      .orElseThrow(() -> new IllegalArgumentException("keyPair.getPublicKey must not be null"));
    this.privateKey = Optional.ofNullable(keyPair.getPrivate())
      .orElseThrow(() -> new IllegalArgumentException("keyair.getPrivateKey must not be null"));
  }

  public AbstractKeyPairCredential(final PublicKey publicKey, final PrivateKey privateKey) {
    this.publicKey = Optional.ofNullable(publicKey).orElseThrow(() -> new IllegalArgumentException("publicKey must not be null"));
    this.privateKey = Optional.ofNullable(privateKey).orElseThrow(() -> new IllegalArgumentException("privateKey must not be null"));
  }

  public AbstractKeyPairCredential(final KeyStore keyStore, final String alias, final char[] keyPassword)
      throws KeyStoreException, UnrecoverableKeyException {
    this(keyStore, alias, keyPassword, null);
  }

  protected AbstractKeyPairCredential(final KeyStore keyStore, final String alias, final char[] keyPassword,
      final X509Certificate certificate) throws KeyStoreException, UnrecoverableKeyException {

    this.keyStore = Optional.ofNullable(keyStore).orElseThrow(() -> new IllegalArgumentException("keyStore must not be null"));
    this.keyStoreAlias = Optional.ofNullable(alias)
      .filter(a -> StringUtils.isNotBlank(a))
      .orElseThrow(() -> new IllegalArgumentException("alias must not be null or blank"));
    this.keyStoreKeyPassword = Optional.ofNullable(keyPassword)
      .map(k -> Arrays.copyOf(k, k.length))
      .orElseThrow(() -> new IllegalArgumentException("keyPassword must not be null"));
    this.keyStoreProvider = this.keyStore.getProvider();

    log.debug("Loading private key and certificate from alias '{}' for the keystore of type {} backed by {} provider ...",
      this.keyStoreAlias, this.keyStore.getType(), Optional.ofNullable(this.keyStoreProvider).map(Provider::getName).orElse("default"));

    try {
      Key key = this.keyStore.getKey(this.keyStoreAlias, this.keyStoreKeyPassword);
      if (key == null) {
        throw new IllegalArgumentException("No private key found under alias - " + this.keyStoreAlias);
      }
      if (!PrivateKey.class.isInstance(key)) {
        throw new UnrecoverableKeyException("The recovered key from the keystore is not a private key");
      }
      this.privateKey = PrivateKey.class.cast(key);
      if (certificate != null) {
        this.certificate = certificate;
      }
      else {
        this.certificate = (X509Certificate) this.keyStore.getCertificate(this.keyStoreAlias);
        if (this.certificate == null) {
          throw new IllegalArgumentException("No certificate found under alias - " + this.keyStoreAlias);
        }
      }
      this.publicKey = this.certificate.getPublicKey();
    }
    catch (NoSuchAlgorithmException e) {
      throw new UnrecoverableKeyException("The algorithm for recovering the private key could not be found - " + e.getMessage());
    }

  }
  
  public AbstractKeyPairCredential(final InputStream keyStoreStream, final char[] storePassword, 
      final String alias, final char[] keyPassword) {
    this(null, null, keyStoreStream, storePassword, alias, keyPassword, null);
  }
  
  public AbstractKeyPairCredential(final Provider provider, final String keyStoreType, final InputStream keyStoreStream, final char[] storePassword, 
      final String alias, final char[] keyPassword) {
    this(provider, keyStoreType, keyStoreStream, storePassword, alias, keyPassword, null);
  }
  
  protected AbstractKeyPairCredential(final Provider provider, final String keyStoreType, final InputStream keyStoreStream, final char[] storePassword, 
      final String alias, final char[] keyPassword, final X509Certificate certificate) {
    
    
    
  }

  /** {@inheritDoc} */
  @Override
  public KeyPair getKeyPair() {
    return new KeyPair(this.getPublicKey(), this.getPrivateKey());
  }

  /** {@inheritDoc} */
  @Override
  public PublicKey getPublicKey() {
    return this.publicKey;
  }

  /** {@inheritDoc} */
  @Override
  public synchronized PrivateKey getPrivateKey() {
    return this.privateKey;
  }
  
}
