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

import static java.math.BigDecimal.ZERO;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Arrays;

import net.sf.ntru.exception.NtruException;

/**
 * A polynomial with {@link BigDecimal} coefficients.
 * Some methods (like <code>add</code>) change the polynomial, others (like <code>mult</code>) do
 * not but return the result as a new polynomial.
 */
public class BigDecimalPolynomial {
    private static final BigDecimal ONE_HALF = new BigDecimal("0.5");
    
    BigDecimal[] coeffs;
    
    /**
     * Constructs a new polynomial with <code>N</code> coefficients initialized to 0.
     * @param N the number of coefficients
     */
    BigDecimalPolynomial(int N) {
        coeffs = new BigDecimal[N];
        for (int i=0; i<N; i++)
            coeffs[i] = ZERO;
    }
    
    /**
     * Constructs a new polynomial with a given set of coefficients.
     * @param coeffs the coefficients
     */
    private BigDecimalPolynomial(BigDecimal[] coeffs) {
        this.coeffs = coeffs;
    }
    
    /**
     * Divides all coefficients by 2.
     */
    public void halve() {
        for (int i=0; i<coeffs.length; i++)
            coeffs[i] = coeffs[i].multiply(ONE_HALF);
    }
    
    /**
     * Multiplies the polynomial by another, taking the indices mod N. Does not
     * change this polynomial but returns the result as a new polynomial.<br/>
     * Both polynomials must have the same number of coefficients.<br/>
     * This method uses the
     * <a href="http://en.wikipedia.org/wiki/Schönhage–Strassen_algorithm">
     * Schönhage–Strassen algorithm</a>.
     * @param poly2
     * @return a new polynomial
     * @throws NtruException if the two polynomials differ in the number of coefficients
     */
    public BigDecimalPolynomial mult(BigIntPolynomial poly2) {
        if (poly2.coeffs.length != coeffs.length)
            throw new NtruException("Number of coefficients must be the same");
        
        BigIntPolynomial poly1 = new BigIntPolynomial(coeffs.length);
        for (int i=0; i<coeffs.length; i++)
            poly1.coeffs[i] = coeffs[i].unscaledValue();
        int scale = coeffs[0].scale();
        
        BigIntPolynomial cBigInt = poly1.multBig(poly2);
        BigDecimalPolynomial c = new BigDecimalPolynomial(cBigInt.coeffs.length);
        for (int i=0; i<c.coeffs.length; i++)
            c.coeffs[i] = new BigDecimal(cBigInt.coeffs[i], scale);
        return c;
    }
    
    /**
     * Adds another polynomial which can have a different number of coefficients.
     * @param b another polynomial
     */
    public void add(BigDecimalPolynomial b) {
      if (b.coeffs.length > coeffs.length) {
          int N = coeffs.length;
          coeffs = Arrays.copyOf(coeffs, b.coeffs.length);
          for (int i=N; i<coeffs.length; i++)
              coeffs[i] = ZERO;
      }
      for (int i=0; i<b.coeffs.length; i++)
          coeffs[i] = coeffs[i].add(b.coeffs[i]);
    }

    /**
     * Rounds all coefficients to the nearest integer.
     * @return a new polynomial with <code>BigInteger</code> coefficients
     */
    public BigIntPolynomial round() {
        int N = coeffs.length;
        BigIntPolynomial p = new BigIntPolynomial(N);
        for (int i=0; i<N; i++)
            p.coeffs[i] = coeffs[i].setScale(0, RoundingMode.HALF_EVEN).toBigInteger();
        return p;
    }
    
    /**
     * Makes a copy of the polynomial that is independent of the original.
     */
    @Override
    public BigDecimalPolynomial clone() {
        return new BigDecimalPolynomial(coeffs.clone());
    }
}