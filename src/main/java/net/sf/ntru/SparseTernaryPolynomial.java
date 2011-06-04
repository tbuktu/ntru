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
import java.util.Arrays;

/**
 * A <code>TernaryPolynomial</code> with a "low" number of nonzero coefficients.
 */
public class SparseTernaryPolynomial implements TernaryPolynomial {
    private int N;
    private int[] ones;
    private int[] negOnes;
    
    /**
     * Constructs a <code>DenseTernaryPolynomial</code> from a <code>IntegerPolynomial</code>. The two polynomials are
     * independent of each other.
     * @param intPoly the original polynomial
     */
    SparseTernaryPolynomial(IntegerPolynomial intPoly) {
        this(intPoly.coeffs);
    }
    
    /**
     * Constructs a new <code>SparseTernaryPolynomial</code> with a given set of coefficients.
     * @param coeffs the coefficients
     */
    SparseTernaryPolynomial(int[] coeffs) {
        N = coeffs.length;
        ones = new int[N];
        negOnes = new int[N];
        int onesIdx = 0;
        int negOnesIdx = 0;
        for (int i=0; i<N; i++) {
            int c = coeffs[i];
            switch(c) {
            case 1:
                ones[onesIdx++] = i; break;
            case -1:
                negOnes[negOnesIdx++] = i; break;
            case 0:
                break;
            default:
                throw new NtruException("Illegal value: " + c + ", must be one of {-1, 0, 1}");
            }
        }
        ones = Arrays.copyOf(ones, onesIdx);
        negOnes = Arrays.copyOf(negOnes, negOnesIdx);
    }
    
    /**
     * Generates a random polynomial with <code>numOnes</code> coefficients equal to 1,
     * <code>numNegOnes</code> coefficients equal to -1, and the rest equal to 0.
     * @param N number of coefficients
     * @param numOnes number of 1's
     * @param numNegOnes number of -1's
     */
    static SparseTernaryPolynomial generateRandom(int N, int numOnes, int numNegOnes) {
        int[] coeffs = Util.generateRandomTernary(N, numOnes, numNegOnes);
        return new SparseTernaryPolynomial(coeffs);
    }
    
    @Override
    public IntegerPolynomial mult(IntegerPolynomial poly2) {
        int[] b = poly2.coeffs;
        if (b.length != N)
            throw new NtruException("Number of coefficients must be the same");
        
        int[] c = new int[N];
        for (int i: ones) {
            int j = N - 1 - i;
            for(int k=N-1; k>=0; k--) {
                c[k] += b[j];
                j--;
                if (j < 0)
                    j = N - 1;
            }
        }
        
        for (int i: negOnes) {
            int j = N - 1 - i;
            for(int k=N-1; k>=0; k--) {
                c[k] -= b[j];
                j--;
                if (j < 0)
                    j = N - 1;
            }
        }
        
        return new IntegerPolynomial(c);
    }
    
    @Override
    public IntegerPolynomial mult(IntegerPolynomial poly2, int modulus) {
        IntegerPolynomial c = mult(poly2);
        c.mod(modulus);
        return c;
    }

    @Override
    public BigIntPolynomial mult(BigIntPolynomial poly2) {
        BigInteger[] b = poly2.coeffs;
        if (b.length != N)
            throw new NtruException("Number of coefficients must be the same");
        
        BigInteger[] c = new BigInteger[N];
        for (int i=0; i<N; i++)
            c[i] = BigInteger.ZERO;
        
        for (int i: ones) {
            int j = N - 1 - i;
            for(int k=N-1; k>=0; k--) {
                c[k] = c[k].add(b[j]);
                j--;
                if (j < 0)
                    j = N - 1;
            }
        }
        
        for (int i: negOnes) {
            int j = N - 1 - i;
            for(int k=N-1; k>=0; k--) {
                c[k] = c[k].subtract(b[j]);
                j--;
                if (j < 0)
                    j = N - 1;
            }
        }
        
        return new BigIntPolynomial(c);
    }
    
    @Override
    public IntegerPolynomial toIntegerPolynomial() {
        int[] coeffs = new int[N];
        for (int i: ones)
            coeffs[i] = 1;
        for (int i: negOnes)
            coeffs[i] = -1;
        return new IntegerPolynomial(coeffs);
    }
    
    @Override
    public void clear() {
        for (int i=0; i<ones.length; i++)
            ones[i] = 0;
        for (int i=0; i<negOnes.length; i++)
            negOnes[i] = 0;
    }
}