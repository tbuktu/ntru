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
import static org.junit.Assert.assertTrue;

import java.math.BigDecimal;
import java.security.SecureRandom;

import net.sf.ntru.polynomial.BigDecimalPolynomial;
import net.sf.ntru.polynomial.BigIntPolynomial;
import net.sf.ntru.polynomial.DenseTernaryPolynomial;
import net.sf.ntru.polynomial.IntegerPolynomial;

import org.junit.Test;

public class BigDecimalPolynomialTest {
    
    @Test
    public void testMult() {
        BigDecimalPolynomial a = createBigDecimalPolynomial(new int[] {4, -1, 9, 2, 1, -5, 12, -7, 0, -9, 5});
        BigIntPolynomial b = new BigIntPolynomial(new IntegerPolynomial(new int[] {-6, 0, 0, 13, 3, -2, -4, 10, 11, 2, -1}));
        BigDecimalPolynomial c = a.mult(b);
        assertArrayEquals(c.coeffs, createBigDecimalPolynomial(new int[] {2, -189, 77, 124, -29, 0, -75, 124, -49, 267, 34}).coeffs);
        
        // multiply a polynomial by its inverse modulo 2048 and check that the result is 1
        IntegerPolynomial d, dInv;
        SecureRandom rng = new SecureRandom();
        do {
            d = DenseTernaryPolynomial.generateRandom(1001, 333, 334, rng);
            dInv = d.invertFq(2048);
        } while (dInv == null);
        d.mod(2048);
        BigDecimalPolynomial e = createBigDecimalPolynomial(d.coeffs);
        BigIntPolynomial f = new BigIntPolynomial(dInv);
        IntegerPolynomial g = new IntegerPolynomial(e.mult(f).round());
        g.modPositive(2048);
        assertTrue(g.equalsOne());
    }
    
    private BigDecimalPolynomial createBigDecimalPolynomial(int[] coeffs) {
        int N = coeffs.length;
        BigDecimalPolynomial poly = new BigDecimalPolynomial(N);
        for (int i=0; i<N; i++)
            poly.coeffs[i] = new BigDecimal(coeffs[i]);
        return poly;
    }
}