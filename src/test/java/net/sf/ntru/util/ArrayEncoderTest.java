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

package net.sf.ntru.util;

import static org.junit.Assert.assertArrayEquals;

import java.util.Random;

import net.sf.ntru.polynomial.PolynomialGeneratorForTesting;
import net.sf.ntru.util.ArrayEncoder;

import org.junit.Test;

public class ArrayEncoderTest {
    
    @Test
    public void testEncodeDecodeModQ() {
        int[] coeffs = PolynomialGeneratorForTesting.generateRandomPositive(1000, 2048).coeffs;
        byte[] data = ArrayEncoder.encodeModQ(coeffs, 2048);
        int[] coeffs2 = ArrayEncoder.decodeModQ(data, 1000, 2048);
        assertArrayEquals(coeffs, coeffs2);
    }
    
    @Test
    public void testEncodeDecodeMod3Sves() {
        Random rng = new Random();
        for (boolean skipFirst: new boolean[] {true, false})
            for (int i=0; i<10; i++) {
                int N = (rng.nextInt(1000)+100) * 16;
                byte[] data = new byte[N*3/16];
                rng.nextBytes(data);
                data[data.length-1] = 0;
                int[] coeffs = ArrayEncoder.decodeMod3Sves(data, N, skipFirst);
                byte[] data2 = ArrayEncoder.encodeMod3Sves(coeffs, skipFirst);
                assertArrayEquals(data, data2);
            }
    }
    
    @Test
    public void testEncodeDecodeMod3Tight() {
        int[] coeffs = PolynomialGeneratorForTesting.generateRandom(1000).coeffs;
        byte[] data = ArrayEncoder.encodeMod3Tight(coeffs);
        int[] coeffs2 = ArrayEncoder.decodeMod3Tight(data, 1000);
        assertArrayEquals(coeffs, coeffs2);
    }
}