/**
 * This software is dual-licensed. You may choose either the
 * Non-Profit Open Software License version 3.0, or any license
 * agreement into which you enter with Security Innovation, Inc.
 * 
 * Use of this code, or certain portions thereof, implements
 * inventions covered by claims of one or more of the following
 * U.S. Patents and/or foreign counterpart patents, owned by
 * Security Innovation, Inc.:
 * 7,308,097, 7,031,468, 6,959,085, 6,298,137, and 6,081,597.
 * Practice or sale of the inventions embodied in the code hereof
 * requires a license from Security Innovation Inc. at:
 * 
 * 187 Ballardvale St, Suite A195
 * Wilmington, MA 01887
 * USA
 */

package net.sf.ntru;

import java.math.BigInteger;

import junit.framework.TestCase;

import org.junit.Test;

public class BigIntEuclideanTest extends TestCase {
    
    @Test
    public void testCalculate() {
        BigIntEuclidean r = BigIntEuclidean.calculate(BigInteger.valueOf(120), BigInteger.valueOf(23));
        assertEquals(BigInteger.valueOf(-9), r.x);
        assertEquals(BigInteger.valueOf(47), r.y);
        assertEquals(BigInteger.valueOf(1), r.gcd);
        
        r = BigIntEuclidean.calculate(BigInteger.valueOf(126), BigInteger.valueOf(231));
        assertEquals(BigInteger.valueOf(2), r.x);
        assertEquals(BigInteger.valueOf(-1), r.y);
        assertEquals(BigInteger.valueOf(21), r.gcd);
    }
}