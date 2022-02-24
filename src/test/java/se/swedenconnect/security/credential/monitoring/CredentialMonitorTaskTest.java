/*
 * Copyright 2020-2022 Sweden Connect
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
package se.swedenconnect.security.credential.monitoring;

import org.junit.Assert;
import org.junit.Test;

import lombok.Getter;

/**
 * Test cases for CredentialMonitorTask.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CredentialMonitorTaskTest {

  @Test(expected = IllegalArgumentException.class)
  public void testNullBean() throws Exception {
    new CredentialMonitorTask(null);
  }
  
  @Test
  public void testRun() throws Exception {
    TestBean bean = new TestBean();
    CredentialMonitorTask task = new CredentialMonitorTask(bean);
    task.run();
    
    Assert.assertEquals(1, bean.getTestCalled());
  }
  
  public static class TestBean implements CredentialMonitorBean {
    
    @Getter
    private int testCalled = 0;

    @Override
    public void test() {
      this.testCalled++;
    }
    
  }

}
