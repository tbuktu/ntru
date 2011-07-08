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

/** A polynomial whose coefficients are all equal to -1, 0, or 1 */
interface TernaryPolynomial {
    
    /** Multiplies the polynomial by an <code>IntegerPolynomial</code>, taking the indices mod N */
    IntegerPolynomial mult(IntegerPolynomial poly2);
    
    /** Multiplies the polynomial by an <code>IntegerPolynomial</code>, taking the coefficient values mod modulus and the indices mod N */
    IntegerPolynomial mult(IntegerPolynomial poly2, int modulus);
    
    /** Multiplies the polynomial by an <code>BigIntPolynomial</code>, taking the indices mod N */
    BigIntPolynomial mult(BigIntPolynomial poly2);
    
    int[] getOnes();
    
    int[] getNegOnes();
    
    IntegerPolynomial toIntegerPolynomial();
    
    /** Returns the maximum number of coefficients the polynomial can have */
    int size();
    
    void clear();
}