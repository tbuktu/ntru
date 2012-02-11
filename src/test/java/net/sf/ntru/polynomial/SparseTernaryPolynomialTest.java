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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Random;

import org.junit.Test;

public class SparseTernaryPolynomialTest {
    
    /** tests mult(IntegerPolynomial) and mult(BigIntPolynomial) */
    @Test
    public void testMult() {
        Random rng = new SecureRandom();
        SparseTernaryPolynomial p1 = SparseTernaryPolynomial.generateRandom(1000, 500, 500, rng);
        IntegerPolynomial p2 = DenseTernaryPolynomial.generateRandom(1000);
        
        IntegerPolynomial prod1 = p1.mult(p2);
        prod1 = p1.mult(p2);
        IntegerPolynomial prod2 = p1.mult(p2);
        assertEquals(prod1, prod2);
        
        BigIntPolynomial p3 = new BigIntPolynomial(p2);
        BigIntPolynomial prod3 = p1.mult(p3);
        assertEquals(new BigIntPolynomial(prod1), prod3);
    }
    
    @Test
    public void testFromToBinary() throws IOException {
        Random rng = new SecureRandom();
        SparseTernaryPolynomial poly1 = SparseTernaryPolynomial.generateRandom(1000, 100, 101, rng);
        ByteArrayInputStream poly1Stream = new ByteArrayInputStream(poly1.toBinary());
        SparseTernaryPolynomial poly2 = SparseTernaryPolynomial.fromBinary(poly1Stream, 1000, 100, 101);
        assertEquals(poly1, poly2);
    }
    
    @Test
    public void testGenerateRandom() {
        Random rng = new Random();
        verify(SparseTernaryPolynomial.generateRandom(743, 248, 248, rng));
        
        for (int i=0; i<10; i++) {
            int N = rng.nextInt(2000) + 10;
            int numOnes = rng.nextInt(N);
            int numNegOnes = rng.nextInt(N-numOnes);
            verify(SparseTernaryPolynomial.generateRandom(N, numOnes, numNegOnes, rng));
        }
    }
    
    private void verify(SparseTernaryPolynomial poly) {
        // make sure ones and negative ones don't share indices
        for (int i: poly.getOnes())
            for (int j: poly.getNegOnes())
                assertTrue(i != j);
    }
}