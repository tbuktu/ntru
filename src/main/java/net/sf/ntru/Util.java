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

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class Util {
//    private static boolean IS_64_BITNESS_KNOWN;
    private static boolean IS_64_BITNESS_KNOWN = true;
//    private static boolean IS_64_BIT_JVM;
    static boolean IS_64_BIT_JVM;

    /** Calculates the inverse of n mod modulus */
    static int invert(int n, int modulus) {
        n %= modulus;
        if (n < 0)
            n += modulus;
        return IntEuclidean.calculate(n, modulus).x;
    }
    
    /** Calculates the inverse of n mod modulus */
    static long invert(long n, long modulus) {
        n %= modulus;
        if (n < 0)
            n += modulus;
        return LongEuclidean.calculate(n, modulus).x;
    }
    
    /** Calculates a^b mod modulus */
    static int pow(int a, int b, int modulus) {
        int p = 1;
        for (int i=0; i<b; i++)
            p = (p*a) % modulus;
        return p;
    }
    
    /** Calculates a^b mod modulus */
    static long pow(long a, int b, long modulus) {
        long p = 1;
        for (int i=0; i<b; i++)
            p = (p*a) % modulus;
        return p;
    }
    
    /**
     * Generates a "sparse" or "dense" polynomial containing numOnes ints equal to 1,
     * numNegOnes int equal to -1, and the rest equal to 0.
     * @param N
     * @param numOnes
     * @param numNegOnes
     * @param sparse whether to create a {@link SparseTernaryPolynomial} or {@link DenseTernaryPolynomial}
     * @return a ternary polynomial
     */
    static TernaryPolynomial generateRandomTernary(int N, int numOnes, int numNegOnes, boolean sparse) {
        if (sparse)
            return SparseTernaryPolynomial.generateRandom(N, numOnes, numNegOnes);
        else
            return DenseTernaryPolynomial.generateRandom(N, numOnes, numNegOnes);
    }
    
    /**
     * Generates an array containing numOnes ints equal to 1,
     * numNegOnes int equal to -1, and the rest equal to 0.
     * @param N
     * @param numOnes
     * @param numNegOnes
     * @return an array of integers
     */
    static int[] generateRandomTernary(int N, int numOnes, int numNegOnes) {
        List<Integer> list = new ArrayList<Integer>();
        for (int i=0; i<numOnes; i++)
            list.add(1);
        for (int i=0; i<numNegOnes; i++)
            list.add(-1);
        while (list.size() < N)
            list.add(0);
        Collections.shuffle(list, new SecureRandom());
        
        int[] arr = new int[N];
        for (int i=0; i<N; i++)
            arr[i] = list.get(i);
        return arr;
    }
    
    static boolean is64BitJVM() {
        if (!IS_64_BITNESS_KNOWN) {
            String arch = System.getProperty("os.arch");
            String sunModel = System.getProperty("sun.arch.data.model");
            IS_64_BIT_JVM = "amd64".equals(arch) || "x86_64".equals(arch) || "ppc64".equals(arch) || "64".equals(sunModel);
        }
        return IS_64_BIT_JVM;
    }
}