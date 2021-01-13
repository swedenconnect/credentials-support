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
package se.swedenconnect.security.credential.test;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;
import org.springframework.context.annotation.Bean;

import lombok.Setter;
import se.swedenconnect.security.credential.converters.PropertyToPrivateKeyConverter;
import se.swedenconnect.security.credential.converters.PropertyToX509CertificateConverter;

/**
 * Application main.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@SpringBootApplication
public class TestApplication implements CommandLineRunner {
  
  @Setter
  @Autowired
  private TestCredentialsService testCredentialsService;

  /**
   * Program main.
   * 
   * @param args
   *          program arguments
   */
  public static void main(String[] args) {
    
    // Initialize OpenSAML ...
    try {
      InitializationService.initialize();
    }
    catch (InitializationException e) {
      throw new RuntimeException("Failed to initialize OpenSAML", e);
    }
    
    SpringApplication.run(TestApplication.class, args);
  }

  /** {@inheritDoc} */
  @Override
  public void run(String... args) throws Exception {
    System.out.println("RUNNING TESTS");
    System.out.println("");
    System.out.print(this.testCredentialsService.test());
  }

  /**
   * Gets the {@link PropertyToX509CertificateConverter} that enables us to point to a certificate on file from a
   * properties file and get a {@link X509Certificate} injected.
   * 
   * @return the PropertyToX509CertificateConverter bean
   */
  @Bean
  @ConfigurationPropertiesBinding
  public PropertyToX509CertificateConverter propertyToX509CertificateConverter() {
    return new PropertyToX509CertificateConverter();
  }

  /**
   * Gets the {@link PropertyToPrivateKeyConverter} that enables us to point to a (non-encrypted) private key of file
   * from a properties file and get a {@link PrivateKey} injected.
   * 
   * @return a PropertyToPrivateKeyConverter bean
   */
  @Bean
  @ConfigurationPropertiesBinding
  public PropertyToPrivateKeyConverter propertyToPrivateKeyConverter() {
    return new PropertyToPrivateKeyConverter();
  }

}
