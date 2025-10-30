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
package se.swedenconnect.security.credential.opensaml;

import jakarta.annotation.Nonnull;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.signature.DEREncodedKeyValue;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.KeyName;
import org.opensaml.xmlsec.signature.X509Data;
import se.swedenconnect.security.credential.PkiCredential;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

/**
 * Function that transform a {@link PkiCredential} into an OpenSAML {@link KeyDescriptor}.
 *
 * @author Martin Lindström
 */
public class KeyDescriptorTransformerFunction implements Function<PkiCredential, KeyDescriptor> {

  /**
   * Given the supplied {@link PkiCredential}, the method creates an OpenSAML {@link KeyDescriptor} for inclusion in an
   * {@link org.opensaml.saml.saml2.metadata.EntityDescriptor EntityDescriptor}.
   * <p>
   * The method will process the following parameters:
   * <ul>
   * <li>
   * The credential name - The name, as given by {@link PkiCredential#getName()} will be used as value for the
   * {@code ds:KeyName} element.
   * </li>
   * <li>
   * The usage - If the metadata property {@link PkiCredential.Metadata#USAGE_PROPERTY} is assigned, and set to either
   * {@link PkiCredential.Metadata#USAGE_SIGNING} or {@link PkiCredential.Metadata#USAGE_ENCRYPTION}, the {@code use}
   * attribute of the {@code md:KeyDescriptor} element will be set accordingly.
   * </li>
   * <li>
   * Encryption methods - If the usage for the credential is encryption (or unspecified), and the metadata property
   * {@link OpenSamlMetadataProperties#ENCRYPTION_METHODS} has been assigned, these values are used to create, and add,
   * {@code md:EncryptionMethod} elements to the resulting {@code md:KeyDescriptor}.
   * </li>
   * </ul>
   * </p>
   *
   * @param credential the credential
   * @return a {@link KeyDescriptor}
   */
  @Override
  @Nonnull
  public KeyDescriptor apply(@Nonnull final PkiCredential credential) {

    final KeyDescriptor keyDescriptor =
        (KeyDescriptor) XMLObjectSupport.buildXMLObject(KeyDescriptor.DEFAULT_ELEMENT_NAME);

    final UsageType usageType = Optional.ofNullable(credential.getMetadata().getUsage())
        .map(u -> PkiCredential.Metadata.USAGE_SIGNING.equals(u) ? UsageType.SIGNING :
            PkiCredential.Metadata.USAGE_ENCRYPTION.equals(u) ? UsageType.ENCRYPTION : null)
        .orElse(null);
    keyDescriptor.setUse(usageType);

    final KeyInfo keyInfo = (KeyInfo) XMLObjectSupport.buildXMLObject(KeyInfo.DEFAULT_ELEMENT_NAME);
    keyDescriptor.setKeyInfo(keyInfo);

    final KeyName keyName = (KeyName) XMLObjectSupport.buildXMLObject(KeyName.DEFAULT_ELEMENT_NAME);
    keyName.setValue(credential.getName());
    keyInfo.getKeyNames().add(keyName);

    final X509Certificate certificate = credential.getCertificate();
    if (certificate != null) {
      try {
        final String base64Encoding = Base64.getEncoder().encodeToString(certificate.getEncoded());
        final X509Data x509Data = (X509Data) XMLObjectSupport.buildXMLObject(X509Data.DEFAULT_ELEMENT_NAME);
        final org.opensaml.xmlsec.signature.X509Certificate cert =
            (org.opensaml.xmlsec.signature.X509Certificate) XMLObjectSupport
                .buildXMLObject(org.opensaml.xmlsec.signature.X509Certificate.DEFAULT_ELEMENT_NAME);
        cert.setValue(base64Encoding);
        x509Data.getX509Certificates().add(cert);
        keyInfo.getX509Datas().add(x509Data);
      }
      catch (final CertificateEncodingException e) {
        throw new SecurityException("Could not encode certificate", e);
      }
    }
    else {
      final DEREncodedKeyValue derEncodedKeyValue =
          (DEREncodedKeyValue) XMLObjectSupport.buildXMLObject(DEREncodedKeyValue.DEFAULT_ELEMENT_NAME);
      derEncodedKeyValue.setValue(Base64.getEncoder().encodeToString(credential.getPublicKey().getEncoded()));
      keyInfo.getDEREncodedKeyValues().add(derEncodedKeyValue);
    }

    if (UsageType.ENCRYPTION == usageType || null == usageType) {
      final List<EncryptionMethodMetadata> methods =
          OpenSamlMetadataProperties.getEncryptionMethods(credential.getMetadata());
      Optional.ofNullable(methods)
          .ifPresent(list -> list.forEach(m -> keyDescriptor.getEncryptionMethods().add(m.toEncryptionMethod())));
    }

    return keyDescriptor;
  }
}
