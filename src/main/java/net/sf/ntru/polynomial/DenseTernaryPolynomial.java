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
import java.util.Arrays;

import net.sf.ntru.exception.NtruException;
import net.sf.ntru.util.Util;

/**
 * A <code>TernaryPolynomial</code> with a "high" number of nonzero coefficients.
 */
public class DenseTernaryPolynomial extends IntegerPolynomial implements TernaryPolynomial {
    
    /**
     * Constructs a new <code>DenseTernaryPolynomial</code> with <code>N</code> coefficients.
     * @param N the number of coefficients
     */
    DenseTernaryPolynomial(int N) {
        super(N);
        checkTernarity();
    }
    
    /**
     * Constructs a <code>DenseTernaryPolynomial</code> from a <code>IntegerPolynomial</code>. The two polynomials are
     * independent of each other.
     * @param intPoly the original polynomial
     */
    public DenseTernaryPolynomial(IntegerPolynomial intPoly) {
        this(intPoly.coeffs);
    }
    
    /**
     * Constructs a new <code>DenseTernaryPolynomial</code> with a given set of coefficients.
     * @param coeffs the coefficients
     */
    public DenseTernaryPolynomial(int[] coeffs) {
        super(coeffs);
        checkTernarity();
    }
    
    private void checkTernarity() {
        for (int c: coeffs)
            if (c<-1 || c>1)
                throw new NtruException("Illegal value: " + c + ", must be one of {-1, 0, 1}");
    }
    
    /**
     * Generates a random polynomial with <code>numOnes</code> coefficients equal to 1,
     * <code>numNegOnes</code> coefficients equal to -1, and the rest equal to 0.
     * @param N number of coefficients
     * @param numOnes number of 1's
     * @param numNegOnes number of -1's
     */
    public static DenseTernaryPolynomial generateRandom(int N, int numOnes, int numNegOnes) {
        int[] coeffs = Util.generateRandomTernary(N, numOnes, numNegOnes);
        return new DenseTernaryPolynomial(coeffs);
    }
    
    /**
     * Generates a polynomial with coefficients randomly selected from <code>{-1, 0, 1}</code>.
     * @param N number of coefficients
     * @return
     */
    public static DenseTernaryPolynomial generateRandom(int N) {
        SecureRandom rng = new SecureRandom();
        DenseTernaryPolynomial poly = new DenseTernaryPolynomial(N);
        for (int i=0; i<N; i++)
            poly.coeffs[i] = rng.nextInt(3) - 1;
        return poly;
    }

    @Override
    public IntegerPolynomial mult(IntegerPolynomial poly2, int modulus) {
        // even on 32-bit systems, LongPolynomial5 multiplies faster than IntegerPolynomial
        if (modulus == 2048) {
            IntegerPolynomial poly2Pos = poly2.clone();
            poly2Pos.modPositive(2048);
            LongPolynomial5 poly5 = new LongPolynomial5(poly2Pos);
            return poly5.mult(this).toIntegerPolynomial();
        }
        else
            return super.mult(poly2, modulus);
    }

    @Override
    public BigIntPolynomial mult(BigIntPolynomial poly2) {
        return poly2.mult(this);
    }

    @Override
    public int[] getOnes() {
        int N = coeffs.length;
        int[] ones = new int[N];
        int onesIdx = 0;
        for (int i=0; i<N; i++) {
            int c = coeffs[i];
            if (c == 1)
                ones[onesIdx++] = i;
        }
        return Arrays.copyOf(ones, onesIdx);
    }
    
    @Override
    public int[] getNegOnes() {
        int N = coeffs.length;
        int[] negOnes = new int[N];
        int negOnesIdx = 0;
        for (int i=0; i<N; i++) {
            int c = coeffs[i];
            if (c == -1)
                negOnes[negOnesIdx++] = i;
        }
        return Arrays.copyOf(negOnes, negOnesIdx);
    }

    @Override
    public IntegerPolynomial toIntegerPolynomial() {
        return this;
    }
    
    @Override
    public int size() {
        return coeffs.length;
    }
}