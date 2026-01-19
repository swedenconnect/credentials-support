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

import org.cryptacular.io.ClassPathResource;
import org.cryptacular.io.Resource;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.metadata.EncryptionMethod;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.signature.DigestMethod;
import se.swedenconnect.opensaml.OpenSAMLInitializer;
import se.swedenconnect.opensaml.OpenSAMLSecurityExtensionConfig;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.KeyStoreFactory;

import java.io.InputStream;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Test cases for {@link KeyDescriptorTransformerFunction}.
 *
 * @author Martin Lindström
 */
public class KeyDescriptorTransformerFunctionTest {

  private final KeyStore keyStore;

  public KeyDescriptorTransformerFunctionTest() throws Exception {
    final Resource resource = new ClassPathResource("keys.jks");
    try (final InputStream inputStream = resource.getInputStream()) {
      this.keyStore = KeyStoreFactory.loadKeyStore(inputStream, "secret".toCharArray(), null, null);
    }
  }

  @BeforeAll
  public static void setUp() throws Exception {
    if (!OpenSAMLInitializer.getInstance().isInitialized()) {
      OpenSAMLInitializer.getInstance().initialize(new OpenSAMLSecurityExtensionConfig());
    }
  }

  @Test
  void testKeyName() throws Exception {
    final PkiCredential credential = new KeyStoreCredential(this.keyStore, "rsa", "secret".toCharArray());

    final KeyDescriptor keyDescriptor = credential.transform(KeyDescriptorTransformerFunction.function());
    Assertions.assertEquals(credential.getName(), keyDescriptor.getKeyInfo().getKeyNames().get(0).getValue());
  }

  @Test
  void testKeyNameCustom() throws Exception {
    final PkiCredential credential = new KeyStoreCredential(this.keyStore, "rsa", "secret".toCharArray());

    final KeyDescriptor keyDescriptor = credential.transform(KeyDescriptorTransformerFunction.function()
        .withKeyNameFunction(c -> "Signing"));
    Assertions.assertEquals("Signing", keyDescriptor.getKeyInfo().getKeyNames().get(0).getValue());
  }

  @Test
  void testUnspecifiedUsageWithCertificate() throws Exception {
    final PkiCredential credential = new KeyStoreCredential(this.keyStore, "rsa", "secret".toCharArray());
    final KeyDescriptorTransformerFunction func = new KeyDescriptorTransformerFunction();
    final KeyDescriptor keyDescriptor = func.apply(credential);

    Assertions.assertNotNull(keyDescriptor);
    Assertions.assertEquals(UsageType.UNSPECIFIED, keyDescriptor.getUse());
    Assertions.assertEquals(credential.getName(), keyDescriptor.getKeyInfo().getKeyNames().get(0).getValue());
    Assertions.assertEquals(Base64.getEncoder().encodeToString(credential.getCertificate().getEncoded()),
        keyDescriptor.getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0).getValue());
  }

  @Test
  void testUsageWithCertificate() throws Exception {
    final PkiCredential credential = new KeyStoreCredential(this.keyStore, "rsa", "secret".toCharArray());
    credential.getMetadata().setUsage(PkiCredential.Metadata.USAGE_SIGNING);
    final KeyDescriptorTransformerFunction func = new KeyDescriptorTransformerFunction();
    final KeyDescriptor keyDescriptor = func.apply(credential);

    Assertions.assertNotNull(keyDescriptor);
    Assertions.assertEquals(UsageType.SIGNING, keyDescriptor.getUse());

    credential.getMetadata().setUsage(PkiCredential.Metadata.USAGE_ENCRYPTION);

    final KeyDescriptor keyDescriptor2 = func.apply(credential);

    Assertions.assertNotNull(keyDescriptor2);
    Assertions.assertEquals(UsageType.ENCRYPTION, keyDescriptor2.getUse());
  }

  @Test
  void testUsageCustom() throws Exception {
    final PkiCredential credential = new KeyStoreCredential(this.keyStore, "rsa", "secret".toCharArray());

    final KeyDescriptorTransformerFunction func = KeyDescriptorTransformerFunction.function()
        .withUsageTypeFunction(c -> UsageType.SIGNING);
    final KeyDescriptor keyDescriptor = func.apply(credential);

    Assertions.assertNotNull(keyDescriptor);
    Assertions.assertEquals(UsageType.SIGNING, keyDescriptor.getUse());
  }

  @Test
  void testEncryptionMethods() throws Exception {
    final PkiCredential credential = new KeyStoreCredential(this.keyStore, "rsa", "secret".toCharArray());
    credential.getMetadata().setUsage(PkiCredential.Metadata.USAGE_ENCRYPTION);

    final List<EncryptionMethodMetadata> methods = new ArrayList<>();
    methods.add(EncryptionMethodMetadata.parseMethod("http://www.w3.org/2009/xmlenc11#aes256-gcm"));
    methods.add(EncryptionMethodMetadata.parseMethod(
        "http://www.w3.org/2009/xmlenc11#rsa-oaep;digest-method=http://www.w3.org/2000/09/xmldsig#sha1"));

    OpenSamlMetadataProperties.setEncryptionMethods(credential.getMetadata(), methods);

    final KeyDescriptorTransformerFunction func = new KeyDescriptorTransformerFunction();
    final KeyDescriptor keyDescriptor = func.apply(credential);

    Assertions.assertNotNull(keyDescriptor);
    Assertions.assertEquals(UsageType.ENCRYPTION, keyDescriptor.getUse());

    Assertions.assertTrue(keyDescriptor.getEncryptionMethods().stream()
        .anyMatch(m -> "http://www.w3.org/2009/xmlenc11#aes256-gcm".equals(m.getAlgorithm())));

    final EncryptionMethod em = keyDescriptor.getEncryptionMethods().stream()
        .filter(m -> "http://www.w3.org/2009/xmlenc11#rsa-oaep".equals(m.getAlgorithm()))
        .findFirst()
        .orElse(null);
    Assertions.assertNotNull(em);
    final DigestMethod dm =
        em.getUnknownXMLObjects().stream()
            .filter(DigestMethod.class::isInstance)
            .map(DigestMethod.class::cast)
            .filter(a -> "http://www.w3.org/2000/09/xmldsig#sha1".equals(a.getAlgorithm()))
            .findFirst()
            .orElse(null);
    Assertions.assertNotNull(dm);
  }

  @Test
  void testEncryptionMethodsCustom() throws Exception {
    final PkiCredential credential = new KeyStoreCredential(this.keyStore, "rsa", "secret".toCharArray());
    credential.getMetadata().setUsage(PkiCredential.Metadata.USAGE_ENCRYPTION);

    final KeyDescriptorTransformerFunction func = KeyDescriptorTransformerFunction.function()
        .withEncryptionMethodsFunction((c, u) -> {
          return List.of(EncryptionMethodMetadata.parseMethod(
                  "http://www.w3.org/2009/xmlenc11#rsa-oaep;digest-method=http://www.w3.org/2000/09/xmldsig#sha1")
              .toEncryptionMethod());
        });

    final KeyDescriptor keyDescriptor = func.apply(credential);

    Assertions.assertNotNull(keyDescriptor);
    Assertions.assertEquals(UsageType.ENCRYPTION, keyDescriptor.getUse());

    final EncryptionMethod em = keyDescriptor.getEncryptionMethods().stream()
        .filter(m -> "http://www.w3.org/2009/xmlenc11#rsa-oaep".equals(m.getAlgorithm()))
        .findFirst()
        .orElse(null);
    Assertions.assertNotNull(em);
    final DigestMethod dm =
        em.getUnknownXMLObjects().stream()
            .filter(DigestMethod.class::isInstance)
            .map(DigestMethod.class::cast)
            .filter(a -> "http://www.w3.org/2000/09/xmldsig#sha1".equals(a.getAlgorithm()))
            .findFirst()
            .orElse(null);
    Assertions.assertNotNull(dm);
  }

  @Test
  void testNoEncryptionMethodsForSigning() throws Exception {
    final PkiCredential credential = new KeyStoreCredential(this.keyStore, "rsa", "secret".toCharArray());
    credential.getMetadata().setUsage(PkiCredential.Metadata.USAGE_SIGNING);

    final List<EncryptionMethodMetadata> methods = new ArrayList<>();
    methods.add(EncryptionMethodMetadata.parseMethod("http://www.w3.org/2009/xmlenc11#aes256-gcm"));
    methods.add(EncryptionMethodMetadata.parseMethod(
        "http://www.w3.org/2009/xmlenc11#rsa-oaep;digest-method=http://www.w3.org/2000/09/xmldsig#sha1"));

    OpenSamlMetadataProperties.setEncryptionMethods(credential.getMetadata(), methods);

    final KeyDescriptorTransformerFunction func = new KeyDescriptorTransformerFunction();
    final KeyDescriptor keyDescriptor = func.apply(credential);

    Assertions.assertNotNull(keyDescriptor);
    Assertions.assertEquals(UsageType.SIGNING, keyDescriptor.getUse());

    Assertions.assertTrue(keyDescriptor.getEncryptionMethods().isEmpty());
  }

  @Test
  void testNoCertRsa() throws Exception {
    final PkiCredential _credential = new KeyStoreCredential(this.keyStore, "rsa", "secret".toCharArray());
    final PkiCredential credential = new BasicCredential(_credential.getPublicKey(), _credential.getPrivateKey());

    final KeyDescriptorTransformerFunction func = new KeyDescriptorTransformerFunction();
    final KeyDescriptor keyDescriptor = func.apply(credential);

    Assertions.assertNotNull(keyDescriptor);
    Assertions.assertTrue(keyDescriptor.getKeyInfo().getX509Datas().isEmpty());
    Assertions.assertTrue(keyDescriptor.getKeyInfo().getDEREncodedKeyValues().size() == 1);
    Assertions.assertArrayEquals(credential.getPublicKey().getEncoded(),
        Base64.getDecoder().decode(keyDescriptor.getKeyInfo().getDEREncodedKeyValues().get(0).getValue()));
  }

  @Test
  void testNoCertEc() throws Exception {
    final PkiCredential _credential = new KeyStoreCredential(this.keyStore, "ec", "secret".toCharArray());
    final PkiCredential credential = new BasicCredential(_credential.getPublicKey(), _credential.getPrivateKey());

    final KeyDescriptorTransformerFunction func = new KeyDescriptorTransformerFunction();
    final KeyDescriptor keyDescriptor = func.apply(credential);

    Assertions.assertNotNull(keyDescriptor);
    Assertions.assertTrue(keyDescriptor.getKeyInfo().getX509Datas().isEmpty());
    Assertions.assertTrue(keyDescriptor.getKeyInfo().getDEREncodedKeyValues().size() == 1);
    Assertions.assertArrayEquals(credential.getPublicKey().getEncoded(),
        Base64.getDecoder().decode(keyDescriptor.getKeyInfo().getDEREncodedKeyValues().get(0).getValue()));
  }

}
