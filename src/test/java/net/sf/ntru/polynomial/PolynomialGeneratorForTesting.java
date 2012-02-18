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

import java.security.SecureRandom;
import java.util.Random;

import net.sf.ntru.polynomial.IntegerPolynomial;

public class PolynomialGeneratorForTesting {
    
    /**
     * Creates a random polynomial with <code>N</code> coefficients
     * such that <code>-q/2 &le; c &lt; q/2</code> for each coefficient <code>c</code>.
     * @param N length of the polynomial
     * @param q coefficients will all be between -q/2 and q/2
     * @return a random polynomial
     */
    public static IntegerPolynomial generateRandom(int N, int q) {
        Random rng = new Random();
        int[] coeffs = new int[N];
        for (int i=0; i<N; i++)
            coeffs[i] = rng.nextInt(q) - q/2;
        return new IntegerPolynomial(coeffs);
    }
    
    /**
     * Creates a random polynomial with <code>N</code> coefficients
     * such that <code>0 &le; c &lt; q</code> for each coefficient <code>c</code>.
     * @param N length of the polynomial
     * @param q coefficients will all be below this number
     * @return a random polynomial
     */
    public static IntegerPolynomial generateRandomPositive(int N, int q) {
        Random rng = new Random();
        int[] coeffs = new int[N];
        for (int i=0; i<N; i++)
            coeffs[i] = rng.nextInt(q);
        return new IntegerPolynomial(coeffs);
    }

    /**
     * Generates a polynomial with coefficients randomly selected from <code>{-1, 0, 1}</code>.
     * @param N number of coefficients
     */
    public static DenseTernaryPolynomial generateRandom(int N) {
        SecureRandom rng = new SecureRandom();
        int[] coeffs = new int[N];
        for (int i=0; i<N; i++)
            coeffs[i] = rng.nextInt(3) - 1;
        return new DenseTernaryPolynomial(coeffs);
    }
}