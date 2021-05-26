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
package se.swedenconnect.security.credential.utils;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.InvalidParameterException;
import java.security.Provider;
import java.security.ProviderException;

/**
 * Utilities for the Java Security Provider class.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ProviderUtils {

  /**
   * Since the `Provider.isConfigured` method does not exist for Java 8, when encapsulate this method.
   * 
   * @param provider
   *          the provider
   * @return true if the provider is configured and false otherwise
   */
  public static boolean isConfigured(final Provider provider) {
    try {
      final Method isConfigured = provider.getClass().getMethod("isConfigured");
      return (Boolean) isConfigured.invoke(provider);
    }
    catch (NoSuchMethodException e) {
      // OK, this is Java 8. Return true (assuming the provider has been configured).
      return true;
    }
    catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException | SecurityException e) {
      return true;
    }
  }

  /**
   * Since we also want to compile for Java 8 (that doesn't have the configure method) we use reflection.
   * 
   * @param provider
   *          the provider
   * @param config
   *          the config data
   * @return an updated provider
   */
  public static Provider configure(final Provider provider, final String config) {
    try {
      final Method configure = provider.getClass().getMethod("configure", String.class);
      return (Provider) configure.invoke(provider, config);
    }
    catch (InvocationTargetException e) {
      if (e.getTargetException() != null) {
        if (e.getTargetException() instanceof RuntimeException) {
          throw (RuntimeException) e.getTargetException();
        }
      }
      throw new SecurityException(e);
    }
    catch (NoSuchMethodException | IllegalAccessException | IllegalArgumentException e) {
      throw new SecurityException(e);
    }
  }

  /**
   * Predicate that tells whether we are working with Java > 8.
   * 
   * @return true if we can assume a Java version greater than 8 and false otherwise
   */
  public static boolean isModernProvider() {
    try {
      Provider.class.getMethod("isConfigured");
      return true;
    }
    catch (NoSuchMethodException | SecurityException e) {
      return false;
    }
  }

  /**
   * If we are running Java 8 the method is used to create a SunPKCS11 provider.
   * 
   * @param configData
   *          config data
   * @return a Provider
   */
  public static Provider java8CreateSunPkcs11Provider(final String configData) {
    try {
      Class<?> clazz = Class.forName("sun.security.pkcs11.SunPKCS11");
      Constructor<?> ctor = clazz.getConstructor(String.class);
      return (Provider) ctor.newInstance(configData);
    }
    catch (InvocationTargetException e) {
      if (e.getTargetException() != null) {
        if (e.getTargetException() instanceof RuntimeException) {
          throw (RuntimeException) e.getTargetException();
        }
      }
      throw new SecurityException(e);
    }
    catch (ClassNotFoundException | NoSuchMethodException | InstantiationException
        | IllegalAccessException | IllegalArgumentException e) {
      throw new SecurityException(e);
    }
  }

  // Hidden
  private ProviderUtils() {
  }

}
