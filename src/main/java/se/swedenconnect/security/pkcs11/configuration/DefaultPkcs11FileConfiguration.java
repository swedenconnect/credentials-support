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
package se.swedenconnect.security.pkcs11.configuration;

import java.io.File;
import java.io.FileInputStream;
import java.util.Scanner;

import javax.annotation.PostConstruct;

import org.apache.commons.lang.StringUtils;

import lombok.extern.slf4j.Slf4j;

/**
 * The default PKCS#11 configuration class for configuring PKCS#11 providers.
 * <p>
 * The configuration file can be set up in two ways;
 * <ol>
 * <li>By assigning the path to an external PKCS#11 configuration file ({@link #setConfigurationFile(String)} or
 * {@link #DefaultPkcs11FileConfiguration(String)}. This is the receommended choice.</li>
 * <li>By assigning each individual setting ({@link #setLibrary(String)}, {@link #setName(String)},
 * {@link #setSlot(String)}, {@link #setSlotListIndex(Integer)}). This is mainly for testing purposes.</li>
 * </ol>
 * Note: If the external configuration file is set, individual settings of library, name, slot or slotListIndex will be
 * ignored.
 * </p>
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class DefaultPkcs11FileConfiguration implements Pkcs11Configuration {

  /** The complete path to the configuration file. */
  private String configurationFile;

  /** The PKCS#11 library path. */
  private String library;

  /** The name of the HSM slot. */
  private String name;

  /** The slot number/id to use. */
  private String slot;

  /** The slot index to use. */
  private Integer slotListIndex;

  /** Whether the configuration file has been parsed. */
  private boolean configFileParsed = false;

  /**
   * Default constructor.
   */
  public DefaultPkcs11FileConfiguration() {
  }

  /**
   * Constructor assigning the external PKCS#11 configuration file.
   * 
   * @param configurationFile
   *          complete path to the PKCS#11 configuration file
   * @throws InvalidPkcs11ConfigurationException
   *           if the supplied configuration file does not exist
   */
  public DefaultPkcs11FileConfiguration(final String configurationFile) throws InvalidPkcs11ConfigurationException {
    this.configurationFile = validateConfigurationFile(configurationFile);
  }

  /**
   * A constructor setting the library, name, slot and slotListIndex individually. See also
   * {@link #DefaultPkcs11FileConfiguration(String)}.
   * 
   * @param library
   *          the PKCS#11 library path
   * @param name
   *          the name of the HSM slot
   * @param slot
   *          the slot number/id (may be null)
   * @param slotListIndex
   *          the slot index (may be null)
   */
  public DefaultPkcs11FileConfiguration(final String library, final String name, final String slot, final Integer slotListIndex) {
    this.library = StringUtils.trim(library);
    this.name = StringUtils.trim(name);
    this.slot = StringUtils.trim(slot);
    if (slotListIndex != null && slotListIndex < 0) {
      throw new IllegalArgumentException("slotListIndex must be 0 or greater");
    }
    this.slotListIndex = slotListIndex;
  }

  /** {@inheritDoc} */
  @Override
  public String getConfigurationData() throws InvalidPkcs11ConfigurationException {
    this.afterPropertiesSet();

    if (this.configurationFile != null) {
      return this.configurationFile;
    }

    // Manual configuration ...
    // See https://stackoverflow.com/questions/46521791/sunpkcs11-provider-in-java-9.
    //
    StringBuffer sb = new StringBuffer("--");

    if (StringUtils.isBlank(this.library)) {
      throw new IllegalArgumentException("library must be set");
    }
    sb.append("library = ").append(this.library).append(System.lineSeparator());

    if (StringUtils.isBlank(this.name)) {
      throw new IllegalArgumentException("name must be set");
    }
    sb.append("name = ").append(this.name).append(System.lineSeparator());

    if (this.slot != null) {
      sb.append("slot = ").append(this.slot).append(System.lineSeparator());
    }
    if (this.slotListIndex != null) {
      sb.append("slotListIndex = ").append(this.slotListIndex).append(System.lineSeparator());
    }

    return sb.toString();
  }

  /**
   * A method that will assert that the configuration is correct.
   * <p>
   * The method will be invoked automatically if a framework that supports the {@code PostConstruct} annotation is used
   * (such as Spring).
   * </p>
   * 
   * @throws Exception
   *           for invalid configuration
   */
  @PostConstruct
  public void afterPropertiesSet() throws InvalidPkcs11ConfigurationException {
    if (this.configurationFile == null) {
      if (StringUtils.isBlank(this.name)) {
        throw new InvalidPkcs11ConfigurationException("Invalid configuration - 'configurationFile' or 'name' must be set");
      }
      if (StringUtils.isBlank(this.library)) {
        throw new InvalidPkcs11ConfigurationException("Invalid configuration - 'configurationFile' or 'library' must be set");
      }
    }
    else {
      if (StringUtils.isNotBlank(this.name) && !this.configFileParsed) {
        log.warn("Invalid configuration - 'configurationFile' and 'name' is set - Value of assigned 'name' will be ignored");
      }
      if (StringUtils.isNotBlank(this.library) && !this.configFileParsed) {
        log.warn("Invalid configuration - 'configurationFile' and 'library' is set - Value of assigned 'library' will be ignored");
      }
      if (StringUtils.isNotBlank(this.slot) && !this.configFileParsed) {
        log.warn("Invalid configuration - 'configurationFile' and 'slot' is set - Value of assigned 'slot' will be ignored");
      }
      if (this.slotListIndex != null && !this.configFileParsed) {
        log.warn(
          "Invalid configuration - 'configurationFile' and 'slotListIndex' is set - Value of assigned 'slotListIndex' will be ignored");
      }
    }
  }

  /**
   * Gets the complete path to the external PKCS#11 configuration file.
   * 
   * @return the path to the external PKCS#11 configuration file or null if this is not set
   */
  public String getConfigurationFile() {
    return this.configurationFile;
  }

  /**
   * Assigns the complete path to the external PKCS#11 configuration file.
   * 
   * @param configurationFile
   *          the path to the external PKCS#11 configuration file
   */
  public void setConfigurationFile(final String configurationFile) {
    this.configurationFile = configurationFile != null ? validateConfigurationFile(configurationFile) : null;
  }

  /** {@inheritDoc} */
  @Override
  public String getLibrary() {
    if (this.library == null) {
      this.parseConfigurationFile();
    }
    return this.library;
  }

  /**
   * Assigns the path to the PKCS#11 library on the host to use for the provider.
   * 
   * @param library
   *          path to PKCS#11 library
   */
  public void setLibrary(final String library) {
    this.library = StringUtils.trim(library);
  }

  /** {@inheritDoc} */
  @Override
  public String getName() {
    if (this.name == null) {
      this.parseConfigurationFile();
    }
    return this.name;
  }

  /**
   * Assigns the name of the HSM slot.
   * 
   * @param name
   *          the name of the HSM slot
   */
  public void setName(final String name) {
    this.name = StringUtils.trim(name);
  }

  /** {@inheritDoc} */
  @Override
  public String getSlot() {
    if (this.slot == null) {
      this.parseConfigurationFile();
    }
    return this.slot;
  }

  /**
   * Assigns the slot number/id to use.
   *
   * @param slot
   *          slot number/id
   */
  public void setSlot(final String slot) {
    this.slot = slot;
  }

  /** {@inheritDoc} */
  @Override
  public Integer getSlotListIndex() {
    if (this.slotListIndex == null) {
      this.parseConfigurationFile();
    }
    return this.slotListIndex;
  }

  /**
   * Assigns the slot list index to use.
   * 
   * @param slotListIndex
   *          slot list index
   */
  public void setSlotListIndex(final Integer slotListIndex) {
    if (slotListIndex != null && slotListIndex < 0) {
      throw new IllegalArgumentException("slotListIndex must be 0 or greater");
    }
    this.slotListIndex = slotListIndex;
  }

  /**
   * Validates that the supplied configuration file exists.
   * 
   * @param configurationFile
   *          the file to check
   * @return the absolute path of the file
   * @throws InvalidPkcs11ConfigurationException
   *           if the file does not exist
   */
  private static String validateConfigurationFile(final String configurationFile) throws InvalidPkcs11ConfigurationException {
    if (StringUtils.isBlank(configurationFile)) {
      throw new InvalidPkcs11ConfigurationException("configurationFile must be set");
    }
    final File file = new File(configurationFile);
    if (!file.exists()) {
      throw new InvalidPkcs11ConfigurationException(String.format("%s does not exist", configurationFile));
    }
    if (!file.isFile()) {
      throw new InvalidPkcs11ConfigurationException(String.format("%s is not a file", configurationFile));
    }
    return file.getAbsolutePath();
  }

  /**
   * Parses the configuration file and assigns the name, library, slot and slotListIndex.
   * 
   * @throws InvalidPkcs11ConfigurationException
   *           for bad configuration
   */
  private void parseConfigurationFile() throws InvalidPkcs11ConfigurationException {
    if (this.configFileParsed) {
      return;
    }
    this.configFileParsed = true;
    Scanner scanner = null;
    try {
      final FileInputStream fis = new FileInputStream(this.configurationFile);
      scanner = new Scanner(fis);
      while (scanner.hasNextLine()) {
        String line = scanner.nextLine();
        line = line.trim();
        if (line.startsWith("#")) {
          continue;
        }
        final String[] tokens = line.split("=");
        if (tokens.length < 2) {
          continue;
        }
        final String cmd = tokens[0].trim();
        final String value = tokens[1].trim();

        if (cmd.equalsIgnoreCase("library")) {
          this.library = value;
        }
        else if (cmd.equalsIgnoreCase("name")) {
          this.name = value;
        }
        else if (cmd.equalsIgnoreCase("slot")) {
          this.slot = value;
        }
        else if (cmd.equalsIgnoreCase("slotListIndex")) {
          this.slotListIndex = Integer.valueOf(value);
        }
      }
    }
    catch (Exception e) {
      throw new InvalidPkcs11ConfigurationException("Failed to parse configuration file", e);
    }
    finally {
      if (scanner != null) {
        scanner.close();
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    try {
      return String.format("configurationData=%s", this.getConfigurationData());
    }
    catch (InvalidPkcs11ConfigurationException e) {
      return String.format("configurationFile='%s', library='%s', name='%s', slot='%s', slotListIndex='%s'",
        this.configurationFile, this.library, this.name, this.slot, this.slotListIndex);
    }
  }

}
