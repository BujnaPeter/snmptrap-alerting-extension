package com.appdynamics.extensions;

import com.appdynamics.extensions.snmp.CommonUtils;
import org.junit.Assert;
import org.junit.Test;
import org.snmp4j.smi.TimeTicks;

import static com.appdynamics.extensions.snmp.CommonUtils.getSysUptime;

public class TimeTicksTest {

    @Test
    public void whenTimeMoreThanIntegerMaxThenTheErrorShouldBeHandled(){
        TimeTicks timeTicks = CommonUtils.getTimeTicks(42234242394967295L);
        Assert.assertTrue(timeTicks.getValue() != 0);
    }




}
