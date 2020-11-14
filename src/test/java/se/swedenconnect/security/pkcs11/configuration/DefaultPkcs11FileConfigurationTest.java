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

import org.junit.Assert;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;

/**
 * Test cases for DefaultPkcs11FileConfiguration.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultPkcs11FileConfigurationTest {

  @Test
  public void testParseConfigurationFile() throws Exception {
    
    DefaultPkcs11FileConfiguration config = new DefaultPkcs11FileConfiguration(
      new ClassPathResource("cfg1.txt").getFile().getAbsolutePath());
    
    Assert.assertEquals("Foo", config.getName());
    Assert.assertEquals("/opt/foo/lib/libpkcs11.so", config.getLibrary());
    Assert.assertNull(config.getSlot());
    Assert.assertNull(config.getSlotListIndex());
    
    // Should also work with a path relative to our location
    config = new DefaultPkcs11FileConfiguration("src/test/resources/cfg2.txt");
    
    Assert.assertEquals("Foo", config.getName());
    Assert.assertEquals("/opt/foo/lib/libpkcs11.so", config.getLibrary());
    Assert.assertEquals("29", config.getSlot());
    Assert.assertEquals(Integer.valueOf(29), config.getSlotListIndex());
  }
  
  @Test(expected = InvalidPkcs11ConfigurationException.class)
  public void testParseConfigurationFileError() throws Exception {
    
    DefaultPkcs11FileConfiguration config = new DefaultPkcs11FileConfiguration(
      new ClassPathResource("cfg3.txt").getFile().getAbsolutePath());

    config.getSlotListIndex();
  }

}
