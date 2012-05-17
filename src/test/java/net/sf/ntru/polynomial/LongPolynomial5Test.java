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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.util.Random;

import net.sf.ntru.polynomial.DenseTernaryPolynomial;
import net.sf.ntru.polynomial.IntegerPolynomial;
import net.sf.ntru.polynomial.LongPolynomial5;

import org.junit.Test;

public class LongPolynomial5Test {
    
    @Test
    public void testMult() {
        testMult(new int[] {2}, new int[] {-1});
        testMult(new int[] {2, 0}, new int[] {-1, 0});
        testMult(new int[] {2, 0, 3}, new int[] {-1, 0, 1});
        testMult(new int[] {2, 0, 3, 1}, new int[] {-1, 0, 1, 1});
        testMult(new int[] {2, 0, 3, 1, 2}, new int[] {-1, 0, 1, 1, 0});
        testMult(new int[] {2, 0, 3, 1, 1, 5}, new int[] {1, -1, 1, 1, 0, 1});
        testMult(new int[] {2, 0, 3, 1, 1, 5, 1, 4}, new int[] {1, 0, 1, 1, -1, 1, 0, -1});
        testMult(new int[] {1368, 2047, 672, 871, 1662, 1352, 1099, 1608}, new int[] {1, 0, 1, 1, -1, 1, 0, -1});

        // test random polynomials
        Random rng = new Random();
        for (int i=0; i<10; i++) {
            int[] coeffs1 = new int[rng.nextInt(2000)+1];
            int[] coeffs2 = PolynomialGeneratorForTesting.generateRandom(coeffs1.length).coeffs;
            testMult(coeffs1, coeffs2);
        }
    }
    
    private void testMult(int[] coeffs1, int[] coeffs2) {
        IntegerPolynomial i1 = new IntegerPolynomial(coeffs1);
        IntegerPolynomial i2 = new IntegerPolynomial(coeffs2);
        
        LongPolynomial5 a = new LongPolynomial5(i1);
        DenseTernaryPolynomial b = new DenseTernaryPolynomial(i2);
        IntegerPolynomial c1 = i1.mult(i2, 2048);
        IntegerPolynomial c2 = a.mult(b).toIntegerPolynomial();
        assertEqualsMod(c1.coeffs, c2.coeffs, 2048);
    }
    
    private void assertEqualsMod(int[] arr1, int[] arr2, int m) {
        assertEquals(arr1.length, arr2.length);
        for (int i=0; i<arr1.length; i++)
            assertEquals((arr1[i]+m)%m, (arr2[i]+m)%m);
    }
    
    @Test
    public void testToIntegerPolynomial() {
        int[] coeffs = new int[] {2, 0, 3, 1, 1, 5, 1, 4};
        LongPolynomial5 p = new LongPolynomial5(new IntegerPolynomial(coeffs));
        assertArrayEquals(coeffs, p.toIntegerPolynomial().coeffs);
    }
}