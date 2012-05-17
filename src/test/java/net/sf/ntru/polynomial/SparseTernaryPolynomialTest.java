/**
 * Copyright (c) 2011, Tim Buktu
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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
        IntegerPolynomial p2 = PolynomialGeneratorForTesting.generateRandom(1000);
        
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
        int N = 1000;
        SparseTernaryPolynomial poly1 = SparseTernaryPolynomial.generateRandom(N, 100, 101, rng);
        ByteArrayInputStream poly1Stream = new ByteArrayInputStream(poly1.toBinary());
        SparseTernaryPolynomial poly2 = SparseTernaryPolynomial.fromBinary(poly1Stream, N);
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