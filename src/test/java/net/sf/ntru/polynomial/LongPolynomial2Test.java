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

import java.util.Random;

import net.sf.ntru.polynomial.IntegerPolynomial;
import net.sf.ntru.polynomial.LongPolynomial2;

import org.junit.Test;

public class LongPolynomial2Test {
    
    @Test
    public void testMult() {
        IntegerPolynomial i1 = new IntegerPolynomial(new int[] {1368, 2047, 672, 871, 1662, 1352, 1099, 1608});
        IntegerPolynomial i2 = new IntegerPolynomial(new int[] {1729, 1924, 806, 179, 1530, 1381, 1695, 60});
        LongPolynomial2 a = new LongPolynomial2(i1);
        LongPolynomial2 b = new LongPolynomial2(i2);
        IntegerPolynomial c1 = i1.mult(i2, 2048);
        IntegerPolynomial c2 = a.mult(b).toIntegerPolynomial();
        assertArrayEquals(c1.coeffs, c2.coeffs);
        
        // test 10 random polynomials
        Random rng = new Random();
        for (int i=0; i<10; i++) {
            int N = 2 + rng.nextInt(2000);
            i1 = PolynomialGeneratorForTesting.generateRandom(N, 2048);
            i2 = PolynomialGeneratorForTesting.generateRandom(N, 2048);
            a = new LongPolynomial2(i1);
            b = new LongPolynomial2(i2);
            c1 = i1.mult(i2);
            c1.modPositive(2048);
            c2 = a.mult(b).toIntegerPolynomial();
            assertArrayEquals(c1.coeffs, c2.coeffs);
        }
    }
    
    @Test
    public void testSubAnd() {
        IntegerPolynomial i1 = new IntegerPolynomial(new int[] {1368, 2047, 672, 871, 1662, 1352, 1099, 1608});
        IntegerPolynomial i2 = new IntegerPolynomial(new int[] {1729, 1924, 806, 179, 1530, 1381, 1695, 60});
        LongPolynomial2 a = new LongPolynomial2(i1);
        LongPolynomial2 b = new LongPolynomial2(i2);
        a.subAnd(b, 2047);
        i1.sub(i2);
        i1.modPositive(2048);
        assertArrayEquals(a.toIntegerPolynomial().coeffs, i1.coeffs);
    }
    
    @Test
    public void testMult2And() {
        IntegerPolynomial i1 = new IntegerPolynomial(new int[] {1368, 2047, 672, 871, 1662, 1352, 1099, 1608});
        LongPolynomial2 i2 = new LongPolynomial2(i1);
        i2.mult2And(2047);
        i1.mult(2);
        i1.modPositive(2048);
        assertArrayEquals(i1.coeffs, i2.toIntegerPolynomial().coeffs);
    }
}