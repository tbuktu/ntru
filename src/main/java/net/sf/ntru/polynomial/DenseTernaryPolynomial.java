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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;

import net.sf.ntru.encrypt.IndexGenerator;

/**
 * A <code>TernaryPolynomial</code> with a "high" number of nonzero coefficients.
 */
public class DenseTernaryPolynomial extends IntegerPolynomial implements TernaryPolynomial {
    
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
    }
    
    /**
     * Generates a random polynomial with <code>numOnes</code> coefficients equal to 1,
     * <code>numNegOnes</code> coefficients equal to -1, and the rest equal to 0.
     * @param N number of coefficients
     * @param numOnes number of 1's
     * @param numNegOnes number of -1's
     * @param rng the random number generator to use
     */
    public static DenseTernaryPolynomial generateRandom(int N, int numOnes, int numNegOnes, Random rng) {
        List<Integer> list = new ArrayList<Integer>();
        for (int i=0; i<numOnes; i++)
            list.add(1);
        for (int i=0; i<numNegOnes; i++)
            list.add(-1);
        while (list.size() < N)
            list.add(0);
        Collections.shuffle(list, rng);
        
        int[] arr = new int[N];
        for (int i=0; i<N; i++)
            arr[i] = list.get(i);
        return new DenseTernaryPolynomial(arr);
    }
    
    /**
     * Generates a blinding polynomial using an {@link IndexGenerator}.
     * @param ig an Index Generator
     * @param N the number of coefficients
     * @param dr the number of ones / negative ones
     * @return a blinding polynomial
     * @see NtruEncrypt#generateBlindingPoly(byte[])
     */
    public static DenseTernaryPolynomial generateBlindingPoly(IndexGenerator ig, int N, int dr) {
    	return new DenseTernaryPolynomial(generateBlindingCoeffs(ig, N, dr));
    }
    
    /**
     * Generates an <code>int</code> array containing <code>dr</code> elements equal to <code>1</code>
     * and <code>dr</code> elements equal to <code>-1</code> using an index generator.
     * @param ig an index generator
     * @param dr number of ones / negative ones
     * @return an array containing numbers between <code>-1</code> and <code>1</code>
     */
    private static int[] generateBlindingCoeffs(IndexGenerator ig, int N, int dr) {
        int[] r = new int[N];
        for (int coeff=-1; coeff<=1; coeff+=2) {
            int t = 0;
            while (t < dr) {
                int i = ig.nextIndex();
                if (r[i] == 0) {
                    r[i] = coeff;
                    t++;
                }
            }
        }
        
        return r;
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
    public int size() {
        return coeffs.length;
    }
}