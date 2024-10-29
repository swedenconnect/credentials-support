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
package se.swedenconnect.security.credential.spring;

import org.springframework.beans.factory.DisposableBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.ReloadablePkiCredential;
import se.swedenconnect.security.credential.converters.PropertyToPrivateKeyConverter;
import se.swedenconnect.security.credential.converters.PropertyToX509CertificateConverter;
import se.swedenconnect.security.credential.monitoring.CredentialMonitorBean;
import se.swedenconnect.security.credential.monitoring.DefaultCredentialMonitorBean;
import se.swedenconnect.security.credential.pkcs11.MockSunPkcs11Provider;
import se.swedenconnect.security.credential.pkcs11.Pkcs11Credential;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * A Spring configuration file that illustrates how credentials are instantiated.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Configuration
@ConfigurationProperties
public class CredentialsConfiguration implements DisposableBean {

  /**
   * Constructor setting up the mocked PKCS#11 provider.
   */
  public CredentialsConfiguration() {
    // Add our mocked PKCS#11 security provider.
    Security.addProvider(new MockSunPkcs11Provider());

    // We let rsa1.jks simulate our PKCS#11 device.
    MockSunPkcs11Provider.MockedPkcs11ResourceHolder.getInstance().setResource(new ClassPathResource("rsa1.jks"));
  }

  /**
   * Removes the mocked PKCS#11 provider.
   */
  @Override
  public void destroy() throws Exception {
    Security.removeProvider(MockSunPkcs11Provider.PROVIDER_BASE_NAME);

    final Provider[] providers = Security.getProviders();
    for (final Provider p : providers) {
      if (p.getName().contains(MockSunPkcs11Provider.PROVIDER_BASE_NAME)) {
        Security.removeProvider(p.getName());
      }
    }
  }

  /**
   * Gets the bean that registers a converter that takes us from a string (in an application properties file) to a
   * {@link PrivateKey} instance.
   *
   * @return a PropertyToPrivateKeyConverter bean
   */
  @Bean
  @ConfigurationPropertiesBinding
  PropertyToPrivateKeyConverter propertyToPrivateKeyConverter() {
    return new PropertyToPrivateKeyConverter();
  }

  /**
   * Gets the bean that registers a converter that takes us from a string (in an application properties file) to a
   * {@link X509Certificate} instance.
   *
   * @return a PropertyToX509CertificateConverter bean
   */
  @Bean
  @ConfigurationPropertiesBinding
  PropertyToX509CertificateConverter propertyToX509CertificateConverter() {
    return new PropertyToX509CertificateConverter();
  }

  /**
   * Gets a {@link BasicCredential} instance based on the application properties prefixed by {@code credential1.}. In
   * our example the application.properties contains:
   *
   * <pre>
   * credential1.private-key=classpath:rsa1.pkcs8.key
   * credential1.certificate=classpath:rsa1.crt
   * credential1.name=Credential-1
   * </pre>
   *
   * @return a BasicCredential instance
   */
  /*
  @Bean("credential1")
  @ConfigurationProperties("credential1")
  PkiCredential credential1() {
    return new BasicCredential();
  }
   */

  /**
   * Gets a {@link KeyStoreCredential} instance based on the application properties prefixed by {@code credential2.}. In
   * our example the application.properties contains:
   *
   * <pre>
   * credential2.resource=classpath:rsa1.jks
   * credential2.password=secret
   * credential2.alias=test
   * credential2.key-password=${credential2.password}
   * credential2.type=JKS
   * </pre>
   *
   * @return a KeyStoreCredential instance
   */
  /*
  @Bean("credential2")
  @ConfigurationProperties("credential2")
  PkiCredential credential2() {
    return new KeyStoreCredential();
  }
   */

  /**
   * Gets a {@link Pkcs11Credential} instance based on the application properties prefixed by {@code credential3.}. In
   * our example the application.properties contains:
   *
   * <pre>
   * credential3.configuration.configuration-file=<complete path to cfg file>
   * credential3.configuration.base-provider-name=MockSunPKCS11
   * credential3.alias=test
   * credential3.pin=secret
   * </pre>
   * <p>
   * Since we are mocking the PKCS#11 security provider we have to handle this bean in a special way. In a real life
   * scenario (where the SunPKCS11 provider is used), the following configuration could be used (with no need for an
   * explicit creation if the DefaultPkcs11Configuration bean).
   * </p>
   *
   * <pre>
   * credential3.configuration-file=<complete path to cfg file>
   * credential3.alias=test
   * credential3.pin=secret
   * </pre>
   *
   * @param pkcs11Configuration
   *          PKCS#11 configuration (needed since we are mocking PKCS#11)
   * @return a Pkcs11Credential instance
   */
  /*
  @Bean("credential3")
  @ConfigurationProperties("credential3")
  ReloadablePkiCredential credential3(final DefaultPkcs11Configuration pkcs11Configuration) {
    final Pkcs11Credential cred = new Pkcs11Credential();
    cred.setConfiguration(pkcs11Configuration);
    return cred;
  }
   */

  /*
  @Bean
  @ConfigurationProperties("credential3.configuration")
  DefaultPkcs11Configuration pkcs11Configuration() {
    return new DefaultPkcs11Configuration();
  }
*/

  /**
   * Gets a {@link KeyStoreCredential} instance that delivers a KeyStore for a PKCS#11 device. It is based on the
   * application properties prefixed by {@code credential4.}. In our example the application.properties contains:
   *
   * <pre>
   * credential4.provider=MockSunPKCS11
   * credential4.pkcs11-configuration=src/test/resources/cfg1.txt
   * credential4.password=secret
   * credential4.alias=test
   * credential4.key-password=${credential4.password}
   * credential4.type=PKCS11
   * credential4.name=Credential-4
   * </pre>
   *
   * @return a KeyStoreCredential instance
   */
  /*
  @Bean("credential4")
  @ConfigurationProperties("credential4")
  ReloadablePkiCredential credential4() {
    return new KeyStoreCredential();
  }
   */

  /*
  @Bean
  CredentialMonitorBean credentialMonitorBean(final List<ReloadablePkiCredential> credentials) {
    final DefaultCredentialMonitorBean monitorBean = new DefaultCredentialMonitorBean(credentials);
    monitorBean.setReloadSuccessCallback((c) -> System.out.println("Credential " + c.getName() + " was reloaded"));
    monitorBean.setFailureCallback((c, e) -> {
      System.out.println(
          "Test of credential " + c.getName() + " failed with exception: " + e.getClass().getSimpleName());
      return true;
    });
    monitorBean.setReloadFailureCallback((c, e) ->
        System.out.println(
            "Reloading of credential " + c.getName() + " failed with exception: " + e.getClass().getSimpleName()));
    return monitorBean;
  }
   */

}
