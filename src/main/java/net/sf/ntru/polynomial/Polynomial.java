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

package net.sf.ntru.polynomial;

public interface Polynomial {
    
    /**
     * Multiplies the polynomial by an <code>IntegerPolynomial</code>,
     * taking the indices mod <code>N</code>.
     * @param poly2 a polynomial
     * @return the product of the two polynomials
     */
    IntegerPolynomial mult(IntegerPolynomial poly2);
    
    /**
     * Multiplies the polynomial by an <code>IntegerPolynomial</code>,
     * taking the coefficient values mod <code>modulus</code> and the indices mod <code>N</code>.
     * @param poly2 a polynomial
     * @param modulus a modulus to apply
     * @return the product of the two polynomials
     */
    IntegerPolynomial mult(IntegerPolynomial poly2, int modulus);
    
    /**
     * Returns a polynomial that is equal to this polynomial (in the sense that {@link #mult(IntegerPolynomial, int)}
     * returns equal <code>IntegerPolynomial</code>s). The new polynomial is guaranteed to be independent of the original.
     * @return a new <code>IntegerPolynomial</code>.
     */
    IntegerPolynomial toIntegerPolynomial();
    
    /**
     * Multiplies the polynomial by a <code>BigIntPolynomial</code>, taking the indices mod N. Does not
     * change this polynomial but returns the result as a new polynomial.<br/>
     * Both polynomials must have the same number of coefficients.
     * @param poly2 the polynomial to multiply by
     * @return a new polynomial
     */
    BigIntPolynomial mult(BigIntPolynomial poly2);
}