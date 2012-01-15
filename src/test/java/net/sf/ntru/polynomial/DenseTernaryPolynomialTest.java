package net.sf.ntru.polynomial;

import static org.junit.Assert.assertTrue;

import java.util.Random;

import org.junit.Test;

public class DenseTernaryPolynomialTest {
    
    @Test
    public void testGenerateRandom() {
        checkTernarity(DenseTernaryPolynomial.generateRandom(1499));
        
        Random rng = new Random();
        for (int i=0; i<10; i++) {
            int N = rng.nextInt(2000) + 10;
            int numOnes = rng.nextInt(N);
            int numNegOnes = rng.nextInt(N-numOnes);
            checkTernarity(DenseTernaryPolynomial.generateRandom(N, numOnes, numNegOnes, rng));
        }
    }
    
    private void checkTernarity(DenseTernaryPolynomial poly) {
        for (int c: poly.coeffs)
            assertTrue(c>=-1 && c<=1);
    }
}