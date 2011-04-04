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

import java.util.Arrays;

/** a "sparsely populated" polynomial whose non-zero coefficients are all equal to -1 or 1 */
public class SparseTernaryPolynomial {
    private int N;
    private int[] ones;
    private int[] negOnes;
    
    SparseTernaryPolynomial(IntegerPolynomial intPoly) {
        N = intPoly.coeffs.length;
        ones = new int[N];
        negOnes = new int[N];
        int onesIdx = 0;
        int negOnesIdx = 0;
        for (int i=0; i<N; i++) {
            int c = intPoly.coeffs[i];
            switch(c) {
            case 1:
                ones[onesIdx++] = i; break;
            case -1:
                negOnes[negOnesIdx++] = i; break;
            case 0:
                break;
            default:
                throw new RuntimeException("Illegal value: " + c + ", must be one of {-1, 0, 1}");
            }
        }
        ones = Arrays.copyOf(ones, onesIdx);
        negOnes = Arrays.copyOf(negOnes, negOnesIdx);
    }
    
    static SparseTernaryPolynomial generateRandom(int N, int numOnes, int numNegOnes) {
        IntegerPolynomial intPoly = IntegerPolynomial.generateRandomSmall(N, numOnes, numNegOnes);
        return new SparseTernaryPolynomial(intPoly);
    }
    
    /** Multiplies the polynomial by an IntegerPolynomial, taking the indices mod N */
    IntegerPolynomial mult(IntegerPolynomial poly2) {
        int[] b = poly2.coeffs;
        if (b.length != N)
            throw new RuntimeException("Number of coefficients must be the same");
        
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
    
    /** Multiplies the polynomial by an IntegerPolynomial, taking the values mod modulus and the indices mod N */
    IntegerPolynomial mult(IntegerPolynomial poly2, int modulus) {
        int[] b = poly2.coeffs;
        if (b.length != N)
            throw new RuntimeException("Number of coefficients must be the same");
        
        int[] c = new int[N];
        for (int i: ones) {
            int j = N - 1 - i;
            for(int k=N-1; k>=0; k--) {
                c[k] += b[j];
                c[k] %= modulus;
                j--;
                if (j < 0)
                    j = N - 1;
            }
        }
        
        for (int i: negOnes) {
            int j = N - 1 - i;
            for(int k=N-1; k>=0; k--) {
                c[k] -= b[j];
                c[k] %= modulus;
                j--;
                if (j < 0)
                    j = N - 1;
            }
        }
        
        return new IntegerPolynomial(c);
    }
    
    IntegerPolynomial toIntegerPolynomial() {
        int[] coeffs = new int[N];
        for (int i: ones)
            coeffs[i] = 1;
        for (int i: negOnes)
            coeffs[i] = -1;
        return new IntegerPolynomial(coeffs);
    }
    
    void clear() {
        for (int i=0; i<ones.length; i++)
            ones[i] = 0;
        for (int i=0; i<negOnes.length; i++)
            negOnes[i] = 0;
    }
}