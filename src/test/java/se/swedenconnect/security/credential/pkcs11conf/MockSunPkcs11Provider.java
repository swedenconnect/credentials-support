/*
 * Copyright 2020-2021 Sweden Connect
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
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidParameterException;
import java.security.Key;
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
 * A mocked provider implementation that mocks a PKCS#11 provider but really is the same as the SUN and SunRsaSign providers (except for
 * supporting PKCS#11 keystores).
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

  protected MockSunPkcs11Provider(String name, String versionStr, String info) {
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
          String line = scanner.nextLine().trim();
          if (line.startsWith("#")) {
            continue;
          }
          if (line.startsWith("library")) {
            librarySet = true;
          }
          else if (line.startsWith("name")) {
            String[] tokens = line.split("=", 2);
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
      MockSunPkcs11Provider newProv = new MockSunPkcs11Provider(PROVIDER_BASE_NAME + "-" + name);
      newProv.configured = true;
      return newProv;
    }
    catch (IOException e) {
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

    public void setMockNoCertificate(boolean mockNoCertificate) {
      this.mockNoCertificate = mockNoCertificate;
    }

    private MockedPkcs11ResourceHolder() {
    }
  }

  public static class MockKeyStoreSpi extends KeyStoreSpi {

    private KeyStoreSpi spi;

    public MockKeyStoreSpi() {
      try {
        Class<?> spiClass = Class.forName("sun.security.provider.JavaKeyStore$JKS");
        Constructor<?> ctor = spiClass.getConstructor();
        this.spi = (KeyStoreSpi) ctor.newInstance();
      }
      catch (ClassNotFoundException | NoSuchMethodException | InstantiationException | IllegalAccessException | IllegalArgumentException
          | InvocationTargetException e) {
        throw new RuntimeException(e);
      }
    }

    @Override
    public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
      if (stream != null) {
        this.spi.engineLoad(stream, password);
      }
      else {
        Resource resource = MockedPkcs11ResourceHolder.getInstance().getResource();
        if (resource == null) {
          throw new IOException("No resource available");
        }
        try (InputStream is = resource.getInputStream()) {
          this.spi.engineLoad(is, password);
        }
      }
    }

    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
      return this.spi.engineGetKey(alias, password);
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
      if (MockedPkcs11ResourceHolder.getInstance().isMockNoCertificate()) {
        return null;
      }      
      return this.spi.engineGetCertificateChain(alias);
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
      if (MockedPkcs11ResourceHolder.getInstance().isMockNoCertificate()) {
        return null;
      }
      return this.spi.engineGetCertificate(alias);
    }

    @Override
    public Date engineGetCreationDate(String alias) {
      return this.spi.engineGetCreationDate(alias);
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
      throw new IllegalArgumentException("Not allowed for PKCS11");
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
      throw new IllegalArgumentException("Not allowed for PKCS11");
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
      throw new IllegalArgumentException("Not allowed for PKCS11");
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {
      throw new IllegalArgumentException("Not allowed for PKCS11");
    }

    @Override
    public Enumeration<String> engineAliases() {
      return this.spi.engineAliases();
    }

    @Override
    public boolean engineContainsAlias(String alias) {
      return this.spi.engineContainsAlias(alias);
    }

    @Override
    public int engineSize() {
      return this.spi.engineSize();
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
      return this.spi.engineIsKeyEntry(alias);
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
      return this.spi.engineIsCertificateEntry(alias);
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
      return this.spi.engineGetCertificateAlias(cert);
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
      throw new IOException("Not allowed for PKCS11");
    }

  }

}
