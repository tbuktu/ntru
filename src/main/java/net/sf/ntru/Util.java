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

public class Util {

    /** Calculates the inverse of n mod modulus */
    static int invert(int n, int modulus) {
        n %= modulus;
        if (n < 0)
            n += modulus;
        return IntEuclidean.calculate(n, modulus).x;
    }
    
    /** Calculates a^b mod modulus */
    static int pow(int a, int b, int modulus) {
        int p = 1;
        for (int i=0; i<b; i++)
            p = (p*a) % modulus;
        return p;
    }
}