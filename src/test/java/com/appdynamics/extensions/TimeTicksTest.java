package com.appdynamics.extensions;

import org.junit.Assert;
import org.junit.Test;
import org.snmp4j.smi.TimeTicks;

import static com.appdynamics.extensions.snmp.CommonUtils.getSysUptime;

public class TimeTicksTest {

    @Test
    public void whenTimeMoreThanIntegerMaxThenTheErrorShouldBeHandled(){
        TimeTicks timeTicks = getTimeTicks(42234242394967295L);
        Assert.assertTrue(timeTicks.getValue() != 0);
    }


    private TimeTicks getTimeTicks(long upTimeInMs) {
        TimeTicks sysUpTime = new TimeTicks();
        int upTime = (int)upTimeInMs;
        sysUpTime.fromMilliseconds(Math.abs(upTime));
        return sysUpTime;
    }

}
