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

/** Extended Euclidean Algorithm in <code>BigInteger</code>s */
public class BigIntEuclidean {
    BigInteger x, y, gcd;
    
    private BigIntEuclidean() {
    }

    /**
     * Runs the EEA on two <code>BigInteger</code>s<br/>
     * Implemented from pseudocode at {@link http://en.wikipedia.org/wiki/Extended_Euclidean_algorithm}.
     * @param a
     * @param b
     * @return a <code>BigIntEuclidean</code> object that contains the result in the variables <code>x</code>, <code>y</code>, and <code>gcd</code>
     */
    static BigIntEuclidean calculate(BigInteger a, BigInteger b) {
        BigInteger x = BigInteger.ZERO;
        BigInteger lastx = BigInteger.ONE;
        BigInteger y = BigInteger.ONE;
        BigInteger lasty = BigInteger.ZERO;
        while (!b.equals(BigInteger.ZERO)) {
            BigInteger quotient = a.divide(b);
            
            BigInteger temp = a;
            a = b;
            b = temp.mod(b);
            
            temp = x;
            x = lastx.subtract(quotient.multiply(x));
            lastx = temp;
            
            temp = y;
            y = lasty.subtract(quotient.multiply(y));
            lasty = temp;
        }
        
        BigIntEuclidean result = new BigIntEuclidean();
        result.x = lastx;
        result.y = lasty;
        result.gcd = a;
        return result;
    }
}