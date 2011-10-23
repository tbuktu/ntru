package net.sf.ntru.polynomial;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

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
     * @return a ternary polynomial
     */
    public static TernaryPolynomial generateRandomTernary(int N, int numOnes, int numNegOnes, boolean sparse) {
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
    public static int[] generateRandomTernary(int N, int numOnes, int numNegOnes) {
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
}