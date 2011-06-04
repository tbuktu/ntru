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

/**
 * Contains a resultant and a polynomial <code>rho</code> such that
 * <code>res = rho*this + t*(x^n-1) for some integer t</code>.
 * @see IntegerPolynomial#resultant()
 * @see IntegerPolynomial#resultant(int)
 * @see LongPolynomial#resultant()
 * @see LongPolynomial#resultant(int)
 */
class Resultant {
    /** A polynomial such that <code>res = rho*this + t*(x^n-1) for some integer t</code> */
    BigIntPolynomial rho;
    /** Resultant of a polynomial with <code>x^n-1</code> */
    BigInteger res;
    
    Resultant(BigIntPolynomial rho, BigInteger res) {
        this.rho = rho;
        this.res = res;
    }
}