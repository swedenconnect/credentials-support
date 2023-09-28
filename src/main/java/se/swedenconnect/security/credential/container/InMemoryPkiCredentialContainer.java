/*
 * Copyright 2020-2023 Sweden Connect
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
package se.swedenconnect.security.credential.container;

import java.security.KeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * An in-memory implementation of the {@link PkiCredentialContainer} interface.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class InMemoryPkiCredentialContainer extends AbstractPkiCredentialContainer {

  /** The credentials for this container. */
  private Map<String, ExtendedBasicCredential> credentials = new ConcurrentHashMap<>();

  /**
   * Constructor loading the security provider identified by {@code providerName}.
   *
   * @param providerName the name of the security provider
   */
  public InMemoryPkiCredentialContainer(final String providerName) {
    super(Security.getProvider(providerName));
  }

  /**
   * Constructor.
   *
   * @param provider the provider that is used to create and manage keys
   */
  public InMemoryPkiCredentialContainer(final Provider provider) {
    super(provider);
  }

  /** {@inheritDoc} */
  @Override
  public String generateCredential(final String keyTypeName)
      throws KeyException, NoSuchAlgorithmException {

    final KeyPairGenerator keyPairGenerator =
        this.getKeyGeneratorFactory(keyTypeName).getKeyPairGenerator(this.getProvider());
    final KeyPair keyPair = keyPairGenerator.generateKeyPair();
    final String alias = this.generateAlias().toString(16);
    final ExtendedBasicCredential credential = new ExtendedBasicCredential(keyPair, alias, this.getKeyValidity());
    try {
      credential.init();
    }
    catch (final Exception e) {
      throw new KeyException("Failed to initialize credential", e);
    }
    this.credentials.put(alias, credential);

    return alias;
  }

  /** {@inheritDoc} */
  @Override
  public PkiCredential getCredential(final String alias) throws PkiCredentialContainerException {
    final PkiCredential credential = this.credentials.get(alias);
    if (credential == null) {
      throw new PkiCredentialContainerException(String.format("Credential with alias '%s' was not found", alias));
    }
    return credential;
  }

  /** {@inheritDoc} */
  @Override
  public void deleteCredential(final String alias) {
    this.credentials.remove(alias);
  }

  /** {@inheritDoc} */
  @Override
  public Instant getExpiryTime(final String alias) throws PkiCredentialContainerException {
    return ExtendedBasicCredential.class.cast(this.getCredential(alias)).getExpiryTime();
  }

  /** {@inheritDoc} */
  @Override
  public List<String> listCredentials() {
    return this.credentials.keySet().stream().collect(Collectors.toList());
  }

  /**
   * A wrapper of {@link BasicCredential} that also includes expiration time.
   *
   * @author Martin Lindström (martin@idsec.se)
   * @author Stefan Santesson (stefan@idsec.se)
   */
  private class ExtendedBasicCredential extends BasicCredential {

    /** The expiry time. */
    private final Instant validTo;

    /**
     * Constructor.
     *
     * @param keyPair the key pair
     * @param alias the alias for this credential
     * @param validity the key validity (may be null)
     */
    public ExtendedBasicCredential(final KeyPair keyPair, final String alias, final Duration validity) {
      super(keyPair.getPublic(), keyPair.getPrivate());
      super.setName(alias);
      this.validTo = validity != null
          ? Instant.now().plusMillis(validity.toMillis())
          : null;
    }

    /**
     * Gets the expiry time of the credential.
     *
     * @return expiry time for the credential or null if the credential never expires
     */
    public Instant getExpiryTime() {
      return this.validTo;
    }

    /**
     * Blocked from usage. The name is hard-wired to the alias.
     */
    @Override
    public void setName(final String name) {
      throw new IllegalArgumentException("The credential name can not be set");
    }

    /**
     * Will remove itself from the container.
     */
    @Override
    public void destroy() throws Exception {
      super.destroy();
      deleteCredential(this.getName());
    }

  }

}
