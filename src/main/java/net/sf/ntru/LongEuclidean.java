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

/** Extended Euclidean Algorithm in <code>long</code>s */
public class LongEuclidean {
    public long x, y, gcd;
    
    private LongEuclidean() { }
    
    /**
     * Runs the EEA on two <code>long</code>s<br/>
     * Implemented from pseudocode at {@link http://en.wikipedia.org/wiki/Extended_Euclidean_algorithm}.
     * @param a
     * @param b
     * @return a <code>LongEuclidean</code> object that contains the result in the variables <code>x</code>, <code>y</code>, and <code>gcd</code>
     */
    public static LongEuclidean calculate(long a, long b) {
        long x = 0;
        long lastx = 1;
        long y = 1;
        long lasty = 0;
        while (b != 0) {
            long quotient = a / b;
            
            long temp = a;
            a = b;
            b = temp % b;
            
            temp = x;
            x = lastx - quotient*x;
            lastx = temp;
            
            temp = y;
            y = lasty - quotient*y;
            lasty = temp;
        }
        
        LongEuclidean result = new LongEuclidean();
        result.x = lastx;
        result.y = lasty;
        result.gcd = a;
        return result;
    }
}