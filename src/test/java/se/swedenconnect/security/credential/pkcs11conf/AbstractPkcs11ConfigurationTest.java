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

import java.io.IOException;
import java.security.PrivateKey;
import java.security.Provider;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

import se.swedenconnect.security.credential.PkiCredential;

/**
 * Test cases for AbstractPkcs11Configuration.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class AbstractPkcs11ConfigurationTest {

  private static final String LIBRARY = "/opt/foo/lib/libpkcs11.so";
  private static final String NAME = "name";
  
  @Test
  public void testDefaultConstructorSetters() throws Exception {
    TestPkcs11Configuration conf = new TestPkcs11Configuration();
    conf.setConfigurationFile(getAbsolutePath("cfg1.txt"));
    
    // Assign the "manual" settings also. But since the config file has been set, they should not be set.
    //
    conf.setLibrary(LIBRARY);
    conf.setName(NAME);
    conf.setSlot("0");
    conf.setSlotListIndex(0);
    
    conf.afterPropertiesSet();
    
    assertEquals(getAbsolutePath("cfg1.txt"), conf.getConfigurationFile());
    assertNull(conf.getLibrary());
    assertNull(conf.getName());
    assertNull(conf.getSlot());
    assertNull(conf.getSlotListIndex());
    
    assertEquals(getAbsolutePath("cfg1.txt"), conf.toString());
  }
  
  @Test
  public void testDefaultConstructorSetters2() throws Exception {
    TestPkcs11Configuration conf = new TestPkcs11Configuration();
    conf.setLibrary("  " + LIBRARY + "  ");
    conf.setName("  " + NAME);
    conf.afterPropertiesSet();
    
    assertNull(conf.getConfigurationFile());
    assertEquals(LIBRARY, conf.getLibrary());
    assertEquals(NAME, conf.getName());
    assertNull(conf.getSlot());
    assertNull(conf.getSlotListIndex());
    
    assertEquals(String.format("library='%s', name='%s', slot='null', slotListIndex='null'", LIBRARY, NAME), conf.toString());
    
    conf = new TestPkcs11Configuration();
    conf.setLibrary(LIBRARY);
    conf.setName(NAME);
    conf.setSlot("    0");
    conf.setSlotListIndex(null);
    conf.afterPropertiesSet();
    
    assertNull(conf.getConfigurationFile());
    assertEquals(LIBRARY, conf.getLibrary());
    assertEquals(NAME, conf.getName());
    assertEquals("0", conf.getSlot());
    assertNull(conf.getSlotListIndex());
    
    conf = new TestPkcs11Configuration();
    conf.setLibrary(LIBRARY);
    conf.setName(NAME);
    conf.setSlot("0");
    conf.setSlotListIndex(3);
    conf.afterPropertiesSet();
    
    assertNull(conf.getConfigurationFile());
    assertEquals(LIBRARY, conf.getLibrary());
    assertEquals(NAME, conf.getName());
    assertEquals("0", conf.getSlot());
    assertEquals(Integer.valueOf(3), conf.getSlotListIndex());
    
    assertEquals(String.format("library='%s', name='%s', slot='0', slotListIndex='3'", LIBRARY, NAME), conf.toString());
  }
  
  @Test
  public void testSetterCfgFileNullifyIndividuals() throws Exception {
    TestPkcs11Configuration conf = new TestPkcs11Configuration();
    
    conf.setLibrary(LIBRARY);
    conf.setName(NAME);
    conf.setSlot("0");
    conf.setSlotListIndex(3);
    
    // This will nullify the above settings
    conf.setConfigurationFile(getAbsolutePath("cfg1.txt"));
    
    assertEquals(getAbsolutePath("cfg1.txt"), conf.getConfigurationFile());
    assertNull(conf.getLibrary());
    assertNull(conf.getName());
    assertNull(conf.getSlot());
    assertNull(conf.getSlotListIndex());
    
    conf.afterPropertiesSet();
    
    assertEquals(getAbsolutePath("cfg1.txt"), conf.getConfigurationFile());
    assertNull(conf.getLibrary());
    assertNull(conf.getName());
    assertNull(conf.getSlot());
    assertNull(conf.getSlotListIndex());
    
    // setConfigurationFile(null) - No nullifying
    conf = new TestPkcs11Configuration();
    
    conf.setLibrary(LIBRARY);
    conf.setName(NAME);
    conf.setSlot("0");
    conf.setSlotListIndex(3);
    
    conf.setConfigurationFile(null);
    conf.afterPropertiesSet();
    
    assertNull(conf.getConfigurationFile());
    assertEquals(LIBRARY, conf.getLibrary());
    assertEquals(NAME, conf.getName());
    assertEquals("0", conf.getSlot());
    assertEquals(Integer.valueOf(3), conf.getSlotListIndex());
  }
  
  @Test
  public void testMissingParams() throws Exception {
    assertThrows(Pkcs11ConfigurationException.class, () -> {
      TestPkcs11Configuration conf = new TestPkcs11Configuration();
      conf.afterPropertiesSet();
    });
  }
  
  @Test
  public void testMissingParams2() throws Exception {
    assertThrows(Pkcs11ConfigurationException.class, () -> {
      TestPkcs11Configuration conf = new TestPkcs11Configuration();
      conf.setName("foo");
      conf.afterPropertiesSet();
    });
  }
  
  @Test
  public void testMissingParams3() throws Exception {
    assertThrows(Pkcs11ConfigurationException.class, () -> {
      TestPkcs11Configuration conf = new TestPkcs11Configuration();
      conf.setLibrary(LIBRARY);
      conf.afterPropertiesSet();
    });
  }
  
  @Test
  public void testAllArgsConstructor() throws Exception {
    TestPkcs11Configuration conf = new TestPkcs11Configuration(LIBRARY, NAME, "0", 3);
    conf.afterPropertiesSet();
    
    assertNull(conf.getConfigurationFile());
    assertEquals(LIBRARY, conf.getLibrary());
    assertEquals(NAME, conf.getName());
    assertEquals("0", conf.getSlot());
    assertEquals(Integer.valueOf(3), conf.getSlotListIndex());
    
    conf = new TestPkcs11Configuration(LIBRARY, NAME, "0", null);
    conf.afterPropertiesSet();
    
    assertNull(conf.getConfigurationFile());
    assertEquals(LIBRARY, conf.getLibrary());
    assertEquals(NAME, conf.getName());
    assertEquals("0", conf.getSlot());
    assertNull(conf.getSlotListIndex());
  }
  
  @Test
  public void testIllegalSlotListIndex() throws Exception {
    assertThrows(IllegalArgumentException.class, () -> {
      TestPkcs11Configuration conf = new TestPkcs11Configuration(LIBRARY, NAME, "0", -2);
      conf.afterPropertiesSet();
    });
  }
  
  @Test
  public void testIllegalSlotListIndex2() throws Exception {
    assertThrows(IllegalArgumentException.class, () -> {
      TestPkcs11Configuration conf = new TestPkcs11Configuration();
      conf.setLibrary(LIBRARY);
      conf.setName(NAME);
      conf.setSlotListIndex(-2);
      conf.afterPropertiesSet();
    });
  }
  
  @Test
  public void testIllegalConfigFile() throws Exception {
    assertThrows(Pkcs11ConfigurationException.class, () -> {
      new TestPkcs11Configuration(null);
    });
  }
  
  @Test
  public void testIllegalConfigFile2() throws Exception {
    assertThrows(Pkcs11ConfigurationException.class, () -> {
      new TestPkcs11Configuration("/opt/foo/not-there.txt");
    });
  }
  
  @Test
  public void testIllegalConfigFile3() throws Exception {
    assertThrows(Pkcs11ConfigurationException.class, () -> {
      new TestPkcs11Configuration(new ClassPathResource("cfg1.txt").getFile().getAbsoluteFile().getParent());
    });
  }
  
  private static String getAbsolutePath(final String resource) throws IOException {
    return (new ClassPathResource(resource)).getFile().getAbsolutePath();
  }
  
  public static class TestPkcs11Configuration extends AbstractPkcs11Configuration {

    public TestPkcs11Configuration() {
      super();
    }

    public TestPkcs11Configuration(String library, String name, String slot, Integer slotListIndex) {
      super(library, name, slot, slotListIndex);
    }

    public TestPkcs11Configuration(String configurationFile) throws Pkcs11ConfigurationException {
      super(configurationFile);
    }

    @Override
    public Provider getProvider() throws Pkcs11ConfigurationException {
      return null;
    }

    @Override
    public Pkcs11ObjectProvider<PrivateKey> getPrivateKeyProvider() {
      return null;
    }

    @Override
    public Pkcs11ObjectProvider<PkiCredential> getCredentialProvider() {
      return null;
    }
    
  }

}
