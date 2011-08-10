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

/** Extended Euclidean Algorithm in <code>int</code>s */
public class IntEuclidean {
    public int x, y, gcd;
    
    private IntEuclidean() { }
    
    /**
     * Runs the EEA on two <code>int</code>s<br/>
     * Implemented from pseudocode on <a href="http://en.wikipedia.org/wiki/Extended_Euclidean_algorithm">Wikipedia</a>.
     * @param a
     * @param b
     * @return a <code>IntEuclidean</code> object that contains the result in the variables <code>x</code>, <code>y</code>, and <code>gcd</code>
     */
    public static IntEuclidean calculate(int a, int b) {
        int x = 0;
        int lastx = 1;
        int y = 1;
        int lasty = 0;
        while (b != 0) {
            int quotient = a / b;
            
            int temp = a;
            a = b;
            b = temp % b;
            
            temp = x;
            x = lastx - quotient*x;
            lastx = temp;
            
            temp = y;
            y = lasty - quotient*y;
            lasty = temp;
        }
        
        IntEuclidean result = new IntEuclidean();
        result.x = lastx;
        result.y = lasty;
        result.gcd = a;
        return result;
    }
}