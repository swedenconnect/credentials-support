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
package se.swedenconnect.security.credential.pkcs11conf;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Enumeration;
import java.util.Scanner;

import org.springframework.core.io.Resource;

/**
 * A mocked provider implementation that mocks a PKCS#11 provider but really is the same as the SUN and SunRsaSign
 * providers (except for supporting PKCS#11 keystores).
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class MockSunPkcs11Provider extends Provider {

  public static final String PROVIDER_BASE_NAME = "MockSunPKCS11";

  private boolean configured = false;

  private static final long serialVersionUID = -135457117436927350L;

  public MockSunPkcs11Provider() {
    this(PROVIDER_BASE_NAME, "1.0.0", "Mock provider");
  }

  protected MockSunPkcs11Provider(final String name) {
    this(name, "1.0.0", "Mock provider");
  }

  protected MockSunPkcs11Provider(final String name, final String versionStr, final String info) {
    super(name, "1.0.0", "Mock provider");

    final Provider sunProvider = Security.getProvider("SUN");
    for (final Object k : sunProvider.keySet()) {
      final String key = String.class.cast(k);
      if (key.startsWith("Provider.id")) {
        continue;
      }
      this.put(k, sunProvider.get(k));
    }
    final Provider sunRsaSignProvider = Security.getProvider("SunRsaSign");
    for (final Object k : sunRsaSignProvider.keySet()) {
      final String key = String.class.cast(k);
      if (key.startsWith("Provider.id")) {
        continue;
      }
      this.put(k, sunRsaSignProvider.get(k));
    }
    this.put("KeyStore.PKCS11", MockKeyStoreSpi.class.getName());
  }

  public static MockSunPkcs11Provider createStaticallyConfigured() {
    final MockSunPkcs11Provider p = new MockSunPkcs11Provider();
    p.configured = true;
    return p;
  }

  /** {@inheritDoc} */
  @Override
  public Provider configure(final String configArg) {
    if (configArg == null) {
      throw new NullPointerException("configArg is null");
    }
    if (this.configured) {
      return this;
    }
    try {
      String configData = null;
      if (configArg.startsWith("--")) {
        configData = configArg.substring(2);
      }
      else {
        configData = Files.readString(Path.of(configArg));
      }
      String name = null;
      boolean librarySet = false;
      try (Scanner scanner = new Scanner(new ByteArrayInputStream(configData.getBytes()))) {
        while (scanner.hasNextLine()) {
          final String line = scanner.nextLine().trim();
          if (line.startsWith("#")) {
            continue;
          }
          if (line.startsWith("library")) {
            librarySet = true;
          }
          else if (line.startsWith("name")) {
            final String[] tokens = line.split("=", 2);
            if (tokens.length == 2) {
              name = tokens[1].trim();
            }
          }
        }
      }
      if (name == null) {
        throw new InvalidParameterException("Invalid configuration data - Missing name");
      }
      if (!librarySet) {
        throw new InvalidParameterException("Invalid configuration data - Missing library");
      }
      final MockSunPkcs11Provider newProv = new MockSunPkcs11Provider(PROVIDER_BASE_NAME + "-" + name);
      newProv.configured = true;
      return newProv;
    }
    catch (final IOException e) {
      throw new InvalidParameterException("Invalid configuration data - " + e.getMessage());
    }
  }

  @Override
  public boolean isConfigured() {
    return this.configured;
  }

  public static class MockedPkcs11ResourceHolder {

    private static final MockedPkcs11ResourceHolder INSTANCE = new MockedPkcs11ResourceHolder();

    private Resource resource;

    private boolean mockNoCertificate = false;

    public static MockedPkcs11ResourceHolder getInstance() {
      return INSTANCE;
    }

    public Resource getResource() {
      return this.resource;
    }

    public void setResource(final Resource resource) {
      this.resource = resource;
    }

    public boolean isMockNoCertificate() {
      return this.mockNoCertificate;
    }

    public void setMockNoCertificate(final boolean mockNoCertificate) {
      this.mockNoCertificate = mockNoCertificate;
    }

    private MockedPkcs11ResourceHolder() {
    }
  }

  public static class MockKeyStoreSpi extends KeyStoreSpi {

    private KeyStore ks;

    public MockKeyStoreSpi() {
      try {
        this.ks = KeyStore.getInstance("JKS");
      }
      catch (final KeyStoreException e) {
        throw new RuntimeException(e);
      }
    }

    @Override
    public void engineLoad(final InputStream stream, final char[] password)
        throws IOException, NoSuchAlgorithmException, CertificateException {
      if (stream != null) {
        this.ks.load(stream, password);
      }
      else {
        final Resource resource = MockedPkcs11ResourceHolder.getInstance().getResource();
        if (resource == null) {
          throw new IOException("No resource available");
        }
        try (InputStream is = resource.getInputStream()) {
          this.ks.load(is, password);
        }
      }
    }

    @Override
    public Key engineGetKey(final String alias, final char[] password)
        throws NoSuchAlgorithmException, UnrecoverableKeyException {
      try {
        return this.ks.getKey(alias, password);
      }
      catch (final KeyStoreException e) {
        throw new RuntimeException(e);
      }
    }

    @Override
    public Certificate[] engineGetCertificateChain(final String alias) {
      if (MockedPkcs11ResourceHolder.getInstance().isMockNoCertificate()) {
        return null;
      }
      try {
        return this.ks.getCertificateChain(alias);
      }
      catch (final KeyStoreException e) {
        return null;
      }
    }

    @Override
    public Certificate engineGetCertificate(final String alias) {
      if (MockedPkcs11ResourceHolder.getInstance().isMockNoCertificate()) {
        return null;
      }
      try {
        return this.ks.getCertificate(alias);
      }
      catch (final KeyStoreException e) {
        return null;
      }
    }

    @Override
    public Date engineGetCreationDate(final String alias) {
      try {
        return this.ks.getCreationDate(alias);
      }
      catch (final KeyStoreException e) {
        return null;
      }
    }

    @Override
    public void engineSetKeyEntry(final String alias, final Key key, final char[] password, final Certificate[] chain)
        throws KeyStoreException {
      throw new IllegalArgumentException("Not allowed for PKCS11");
    }

    @Override
    public void engineSetKeyEntry(final String alias, final byte[] key, final Certificate[] chain)
        throws KeyStoreException {
      throw new IllegalArgumentException("Not allowed for PKCS11");
    }

    @Override
    public void engineSetCertificateEntry(final String alias, final Certificate cert) throws KeyStoreException {
      throw new IllegalArgumentException("Not allowed for PKCS11");
    }

    @Override
    public void engineDeleteEntry(final String alias) throws KeyStoreException {
      throw new IllegalArgumentException("Not allowed for PKCS11");
    }

    @Override
    public Enumeration<String> engineAliases() {
      try {
        return this.ks.aliases();
      }
      catch (final KeyStoreException e) {
        throw new RuntimeException(e);
      }
    }

    @Override
    public boolean engineContainsAlias(final String alias) {
      try {
        return this.ks.containsAlias(alias);
      }
      catch (final KeyStoreException e) {
        return false;
      }
    }

    @Override
    public int engineSize() {
      try {
        return this.ks.size();
      }
      catch (final KeyStoreException e) {
        throw new RuntimeException(e);
      }
    }

    @Override
    public boolean engineIsKeyEntry(final String alias) {
      try {
        return this.ks.isKeyEntry(alias);
      }
      catch (final KeyStoreException e) {
        return false;
      }
    }

    @Override
    public boolean engineIsCertificateEntry(final String alias) {
      try {
        return this.ks.isCertificateEntry(alias);
      }
      catch (final KeyStoreException e) {
        return false;
      }
    }

    @Override
    public String engineGetCertificateAlias(final Certificate cert) {
      try {
        return this.ks.getCertificateAlias(cert);
      }
      catch (final KeyStoreException e) {
        throw new RuntimeException(e);
      }
    }

    @Override
    public void engineStore(final OutputStream stream, final char[] password)
        throws IOException, NoSuchAlgorithmException, CertificateException {
      throw new IOException("Not allowed for PKCS11");
    }

  }

}
