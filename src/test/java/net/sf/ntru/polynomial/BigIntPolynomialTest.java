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

import java.math.BigInteger;
import java.util.Random;

import net.sf.ntru.polynomial.BigIntPolynomial;
import net.sf.ntru.polynomial.IntegerPolynomial;

import org.junit.Test;

public class BigIntPolynomialTest {
    
    @Test
    public void testMult() {
        BigIntPolynomial a = new BigIntPolynomial(new IntegerPolynomial(new int[] {4, -1, 9, 2, 1, -5, 12, -7, 0, -9, 5}));
        BigIntPolynomial b = new BigIntPolynomial(new IntegerPolynomial(new int[] {-6, 0, 0, 13, 3, -2, -4, 10, 11, 2, -1}));
        BigIntPolynomial expected = new BigIntPolynomial(new IntegerPolynomial(new int[] {2, -189, 77, 124, -29, 0, -75, 124, -49, 267, 34}));
        assertArrayEquals(expected.coeffs, a.multSmall(b).coeffs);
        assertArrayEquals(expected.coeffs, a.multBig(b).coeffs);
        
        Random rng = new Random();
        BigInteger[] aCoeffs = new BigInteger[10+rng.nextInt(50)];
        BigInteger[] bCoeffs = new BigInteger[aCoeffs.length];
        for (int i=0; i<3; i++) {
            for (int j=0; j<aCoeffs.length; j++) {
                byte[] aArr = new byte[600+rng.nextInt(100)];
                rng.nextBytes(aArr);
                aCoeffs[j] = new BigInteger(aArr);
                byte[] bArr = new byte[600+rng.nextInt(100)];
                rng.nextBytes(bArr);
                bCoeffs[j] = new BigInteger(bArr);
            }
            a = new BigIntPolynomial(aCoeffs);
            b = new BigIntPolynomial(bCoeffs);
            assertArrayEquals(a.multSmall(b).coeffs, a.multBig(b).coeffs);
        }
    }
}