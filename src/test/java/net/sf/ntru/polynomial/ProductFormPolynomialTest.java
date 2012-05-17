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

import java.security.SecureRandom;
import java.util.Random;

import net.sf.ntru.encrypt.EncryptionParameters;

import org.junit.Before;
import org.junit.Test;

public class ProductFormPolynomialTest {
    private EncryptionParameters params;
    private int N;
    private int df1;
    private int df2;
    private int df3;
    private int q;
    private Random rng;
    
    @Before
    public void setUp() {
        params = EncryptionParameters.APR2011_439_FAST;
        N = params.N;
        df1 = params.df1;
        df2 = params.df2;
        df3 = params.df3;
        q = params.q;
        rng = new SecureRandom();
    }
    
    @Test
    public void testFromToBinary() {
        ProductFormPolynomial p1 = ProductFormPolynomial.generateRandom(N, df1, df2, df3, df3-1, rng);
        byte[] bin1 = p1.toBinary();
        ProductFormPolynomial p2 = ProductFormPolynomial.fromBinary(bin1, N);
        assertEquals(p1, p2);
    }
    
    @Test
    public void testMult() {
        ProductFormPolynomial p1 = ProductFormPolynomial.generateRandom(N, df1, df2, df3, df3-1, rng);
        IntegerPolynomial p2 = PolynomialGeneratorForTesting.generateRandom(N, q);
        IntegerPolynomial p3 = p1.mult(p2);
        IntegerPolynomial p4 = p1.toIntegerPolynomial().mult(p2);
        assertEquals(p3, p4);
    }
}