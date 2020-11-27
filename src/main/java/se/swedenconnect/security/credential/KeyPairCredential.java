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
package se.swedenconnect.security.credential;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.function.Supplier;

import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;

/**
 * A representation of a PKI key pair.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface KeyPairCredential extends InitializingBean, DisposableBean {

  /**
   * Gets the public key.
   * 
   * @return the public key
   */
  PublicKey getPublicKey();

  /**
   * Gets the certificate holding the public key of the key pair. May be null depending on whether certificates are
   * handled by the implementing class.
   * 
   * @return the certificate, or null if no certificate is configured for the key pair
   */
  X509Certificate getCertificate();

  /**
   * Gets the private key.
   * 
   * @return the private key
   */
  PrivateKey getPrivateKey();

  /**
   * Gets the name of the credential.
   * 
   * @return the name
   */
  String getName();

  /**
   * The {@code init} method is here just because it is a nicer name for {@code afterPropertiesSet}. Should be manually
   * invoked if the instance is not instantiated as a Spring bean.
   * 
   * @throws Exception
   *           for init errors
   */
  default void init() throws Exception {
    this.afterPropertiesSet();
  }

  /**
   * A credential may be monitored to ensure that it is functional. This can be useful when using for example
   * credentials residing on hardware devices where the connection may be lost. If a credential implementation should be
   * "testable" it must return a function for testing itself. This function ({@link Supplier}) returns an
   * {@link Exception} for test failures and {@code null} for success.
   * <p>
   * The default implementation returns {@code null}, meaning that the credential is not "testable".
   * </p>
   * <p>
   * A credential that returns a function should also implement the {@link #reload()} method.
   * </p>
   * 
   * @return a function for testing the credential
   */
  default Supplier<Exception> getTestFunction() {
    return null;
  }

  /**
   * Some implementations of key pairs, such as HSM-based, may need to be reloaded. The default implementation does
   * nothing.
   * 
   * @throws Exception
   *           for reloading errors
   */
  default void reload() throws Exception {
  }

}
