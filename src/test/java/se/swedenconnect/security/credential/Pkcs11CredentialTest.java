/*
 * Copyright 2020-2024 Sweden Connect
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
package se.swedenconnect.security.credential;

import java.lang.reflect.Field;
import java.security.KeyException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

import se.swedenconnect.security.credential.factory.KeyStoreFactoryBean;
import se.swedenconnect.security.credential.monitoring.DefaultCredentialTestFunction;
import se.swedenconnect.security.credential.pkcs11conf.Pkcs11ConfigurationException;

/**
 * Test cases for Pkcs11Credential.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class Pkcs11CredentialTest {

  private final static char[] PIN = "secret".toCharArray();
  private final static String ALIAS = "test";

  private KeyStore keyStore;
  private X509Certificate cert;

  public Pkcs11CredentialTest() throws Exception {
    KeyStoreFactoryBean factory = new KeyStoreFactoryBean(new ClassPathResource("rsa1.jks"), "secret".toCharArray());
    factory.afterPropertiesSet();
    this.keyStore = factory.getObject();
    this.cert = (X509Certificate) this.keyStore.getCertificate(ALIAS);
  }

  @Test
  public void testDefaultConstructor() throws Exception {
    Pkcs11Credential cred = new Pkcs11Credential();
    try {
      cred.afterPropertiesSet();
      fail("Expected IllegalArgumentException");
    }
    catch (IllegalArgumentException e) {
    }

    final MockPkcs11Configuration conf = new MockPkcs11Configuration(this.keyStore);
    cred.setConfiguration(conf);
    try {
      cred.afterPropertiesSet();
      fail("Expected IllegalArgumentException");
    }
    catch (IllegalArgumentException e) {
    }

    cred.setAlias(ALIAS);
    try {
      cred.afterPropertiesSet();
      fail("Expected IllegalArgumentException");
    }
    catch (IllegalArgumentException e) {
    }

    cred.setPin(PIN);
    cred.afterPropertiesSet();

    assertNotNull(cred.getPrivateKey());
    assertNotNull(cred.getPublicKey());
    assertNotNull(cred.getCertificate());
    assertNotNull(cred.getName());
  }

  @Test
  public void testConstructorAll() throws Exception {
    Pkcs11Credential cred = new Pkcs11Credential(null, null, null);
    try {
      cred.afterPropertiesSet();
      fail("Expected IllegalArgumentException");
    }
    catch (IllegalArgumentException e) {
    }

    final MockPkcs11Configuration conf = new MockPkcs11Configuration(this.keyStore);
    cred = new Pkcs11Credential(conf, null, null);
    try {
      cred.afterPropertiesSet();
      fail("Expected IllegalArgumentException");
    }
    catch (IllegalArgumentException e) {
    }

    cred = new Pkcs11Credential(conf, ALIAS, null);
    try {
      cred.afterPropertiesSet();
      fail("Expected IllegalArgumentException");
    }
    catch (IllegalArgumentException e) {
    }

    cred = new Pkcs11Credential(conf, ALIAS, PIN);
    cred.afterPropertiesSet();

    assertNotNull(cred.getPrivateKey());
    assertNotNull(cred.getPublicKey());
    assertNotNull(cred.getCertificate());
    assertNotNull(cred.getName());

    // Make sure nothing bad happens if we call afterPropertiesSet several times ...
    cred.afterPropertiesSet();

    assertNotNull(cred.getPrivateKey());
    assertNotNull(cred.getPublicKey());
    assertNotNull(cred.getCertificate());
    assertNotNull(cred.getName());
    assertTrue(cred.isHardwareCredential());
  }

  @Test
  public void testConstructorAllWithCert() throws Exception {
    Pkcs11Credential cred = new Pkcs11Credential(null, null, null, (X509Certificate) null);
    try {
      cred.afterPropertiesSet();
      fail("Expected IllegalArgumentException");
    }
    catch (IllegalArgumentException e) {
    }

    final MockPkcs11Configuration conf = new MockPkcs11Configuration(this.keyStore);
    conf.setSimulateNoCertificate(true);
    cred = new Pkcs11Credential(conf, null, null, (X509Certificate) null);
    try {
      cred.afterPropertiesSet();
      fail("Expected IllegalArgumentException");
    }
    catch (IllegalArgumentException e) {
    }

    cred = new Pkcs11Credential(conf, ALIAS, null, (X509Certificate) null);
    try {
      cred.afterPropertiesSet();
      fail("Expected IllegalArgumentException");
    }
    catch (IllegalArgumentException e) {
    }

    cred = new Pkcs11Credential(conf, ALIAS, PIN, (X509Certificate) null);
    try {
      cred.afterPropertiesSet();
      fail("Expected IllegalArgumentException");
    }
    catch (IllegalArgumentException e) {
    }

    cred = new Pkcs11Credential(conf, ALIAS, PIN, this.cert);
    cred.afterPropertiesSet();

    assertNotNull(cred.getPrivateKey());
    assertNotNull(cred.getPublicKey());
    assertNotNull(cred.getCertificate());
    assertNotNull(cred.getName());
  }

  @Test
  public void testNoPrivateKey() throws Exception {
    assertThrows(IllegalArgumentException.class, () -> {
      KeyStoreFactoryBean factory = new KeyStoreFactoryBean(new ClassPathResource("aes.jceks"), "secret".toCharArray(), "JCEKS");
      factory.afterPropertiesSet();
      KeyStore aesKeystore = factory.getObject();

      final MockPkcs11Configuration conf = new MockPkcs11Configuration(aesKeystore);
      conf.setSimulateNoCertificate(true);

      final Pkcs11Credential cred = new Pkcs11Credential(conf, ALIAS, PIN, this.cert);
      cred.init();
    });
  }

  @Test
  public void missingCredential() throws Exception {
    assertThrows(IllegalArgumentException.class, () -> {
      final MockPkcs11Configuration conf = new MockPkcs11Configuration(this.keyStore);
      final Pkcs11Credential cred = new Pkcs11Credential(conf, "non-existing", PIN);
      cred.init();
    });
  }

  @Test
  public void installOwnTestFunction() throws Exception {

    final MockPkcs11Configuration conf = new MockPkcs11Configuration(this.keyStore);
    final Pkcs11Credential cred = new Pkcs11Credential(conf, ALIAS, PIN);
    cred.setTestFunction(new DefaultCredentialTestFunction());
    cred.init();

    assertNotNull(cred.getPrivateKey());
    assertNotNull(cred.getPublicKey());
    assertNotNull(cred.getCertificate());
    assertNotNull(cred.getTestFunction());
  }

  @Test
  public void testDefaultTestFunction() throws Exception {

    final MockPkcs11Configuration conf = new MockPkcs11Configuration(this.keyStore);
    final Pkcs11Credential cred = new Pkcs11Credential(conf, ALIAS, PIN);
    cred.init();

    assertNotNull(cred.getPrivateKey());
    assertNotNull(cred.getPublicKey());
    assertNotNull(cred.getCertificate());
    assertNotNull(cred.getTestFunction());
  }

  @Test
  public void testLoadAtGet() throws Exception {
    final MockPkcs11Configuration conf = new MockPkcs11Configuration(this.keyStore);
    Pkcs11Credential cred = new Pkcs11Credential(conf, ALIAS, PIN);
    // No init ...

    assertNotNull(cred.getPrivateKey());
    assertNotNull(cred.getPublicKey());
    assertNotNull(cred.getCertificate());

    cred = new Pkcs11Credential(conf, ALIAS, PIN);
    assertNotNull(cred.getPublicKey());
    assertNotNull(cred.getCertificate());
    assertNotNull(cred.getPrivateKey());

    cred = new Pkcs11Credential(conf, ALIAS, PIN);
    assertNotNull(cred.getCertificate());
    assertNotNull(cred.getPrivateKey());
    assertNotNull(cred.getPublicKey());
  }

  @Test
  public void testLoadAtGetErrors() throws Exception {
    Pkcs11Credential cred = new Pkcs11Credential();
    // No init ...

    try {
      cred.getPrivateKey();
      fail("Expected SecurityException");
    }
    catch (SecurityException e) {
    }

    cred = new Pkcs11Credential();
    try {
      cred.getPublicKey();
      fail("Expected SecurityException");
    }
    catch (SecurityException e) {
    }

    cred = new Pkcs11Credential();
    try {
      cred.getCertificate();
      fail("Expected SecurityException");
    }
    catch (SecurityException e) {
    }
  }

  @Test
  public void testIllegalSetPrivateKey() throws Exception {
    assertThrows(IllegalArgumentException.class, () -> {
      PrivateKey pk = (PrivateKey) this.keyStore.getKey(ALIAS, PIN);

      Pkcs11Credential cred = new Pkcs11Credential();
      cred.setPrivateKey(pk);
    });
  }

  @Test
  public void testIllegalSetPublicKey() throws Exception {
    assertThrows(IllegalArgumentException.class, () -> {
      Pkcs11Credential cred = new Pkcs11Credential();
      cred.setPublicKey(this.cert.getPublicKey());
    });
  }

  @Test
  public void testAssignPkcs11ConfigurationFile() throws Exception {
    Pkcs11Credential cred = new Pkcs11Credential();
    cred.setConfigurationFile(new ClassPathResource("cfg1.txt").getFile().getAbsolutePath());
  }

  @Test
  public void testAssignPkcs11ConfigurationFileError() throws Exception {
    assertThrows(Pkcs11ConfigurationException.class, () -> {
      Pkcs11Credential cred = new Pkcs11Credential();
      cred.setConfigurationFile("/dummy/file/path/conf.cfg");
    });
  }

  @Test
  public void testReload() throws Exception {
    final MockPkcs11Configuration conf = new MockPkcs11Configuration(this.keyStore);
    final Pkcs11Credential cred = new Pkcs11Credential(conf, ALIAS, PIN);
    cred.init();

    assertNotNull(cred.getPrivateKey());
    // Mess up the private key
    Field pk = AbstractPkiCredential.class.getDeclaredField("privateKey");
    pk.setAccessible(true);
    pk.set(cred, null);

    cred.reload();
    assertNotNull(cred.getPrivateKey());
  }

  @Test
  public void testReloadNoInit() throws Exception {
    assertThrows(SecurityException.class, () -> {
      final Pkcs11Credential cred = new Pkcs11Credential();
      cred.reload();
    });
  }

  @Test
  public void testReloadNoInit2() throws Exception {
    assertThrows(SecurityException.class, () -> {
      final MockPkcs11Configuration conf = new MockPkcs11Configuration(this.keyStore);
      final Pkcs11Credential cred = new Pkcs11Credential(conf, null, null);
      cred.reload();
    });
  }

  @Test
  public void testReloadNoInit3() throws Exception {
    assertThrows(SecurityException.class, () -> {
      final MockPkcs11Configuration conf = new MockPkcs11Configuration(this.keyStore);
      final Pkcs11Credential cred = new Pkcs11Credential(conf, ALIAS, null);
      cred.reload();
    });
  }

  @Test
  public void testReloadNoPrivateKey() throws Exception {
    assertThrows(KeyException.class, () -> {
      final MockPkcs11Configuration conf = new MockPkcs11Configuration(this.keyStore);
      final Pkcs11Credential cred = new Pkcs11Credential(conf, ALIAS, PIN);
      cred.init();

      conf.setSimulateNoPrivateKey(true);

      cred.reload();
    });
  }

  @Test
  public void testDestroy() throws Exception {
    final MockPkcs11Configuration conf = new MockPkcs11Configuration(this.keyStore);
    final Pkcs11Credential cred = new Pkcs11Credential(conf, ALIAS, PIN);
    cred.init();

    // Destroy clears the PIN so a reload should fail ...
    cred.destroy();

    try {
      cred.reload();
      fail("Expected SecurityException");
    }
    catch (SecurityException e) {
    }
  }

  @Test
  public void testDestroyUninitialized() throws Exception {
    final Pkcs11Credential cred = new Pkcs11Credential();

    // Just to make sure that destroy doesn't crash if called for a non-initialized object ...
    cred.destroy();
  }

}
