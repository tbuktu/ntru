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

import java.util.Random;

/** Static utility class */
public class PolynomialGenerator {
    
    private PolynomialGenerator() { }
    
    /**
     * Generates a "sparse" or "dense" polynomial containing numOnes ints equal to 1,
     * numNegOnes int equal to -1, and the rest equal to 0.
     * @param N
     * @param numOnes
     * @param numNegOnes
     * @param sparse whether to create a {@link SparseTernaryPolynomial} or {@link DenseTernaryPolynomial}
     * @param rng the random number generator to use
     * @return a ternary polynomial
     */
    public static TernaryPolynomial generateRandomTernary(int N, int numOnes, int numNegOnes, boolean sparse, Random rng) {
        if (sparse)
            return SparseTernaryPolynomial.generateRandom(N, numOnes, numNegOnes, rng);
        else
            return DenseTernaryPolynomial.generateRandom(N, numOnes, numNegOnes, rng);
    }
}