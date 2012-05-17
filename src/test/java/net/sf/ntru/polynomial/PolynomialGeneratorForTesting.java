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

import java.security.SecureRandom;
import java.util.Random;

import net.sf.ntru.polynomial.IntegerPolynomial;

public class PolynomialGeneratorForTesting {
    
    /**
     * Creates a random polynomial with <code>N</code> coefficients
     * such that <code>-q/2 &le; c &lt; q/2</code> for each coefficient <code>c</code>.
     * @param N length of the polynomial
     * @param q coefficients will all be between -q/2 and q/2
     * @return a random polynomial
     */
    public static IntegerPolynomial generateRandom(int N, int q) {
        Random rng = new Random();
        int[] coeffs = new int[N];
        for (int i=0; i<N; i++)
            coeffs[i] = rng.nextInt(q) - q/2;
        return new IntegerPolynomial(coeffs);
    }
    
    /**
     * Creates a random polynomial with <code>N</code> coefficients
     * such that <code>0 &le; c &lt; q</code> for each coefficient <code>c</code>.
     * @param N length of the polynomial
     * @param q coefficients will all be below this number
     * @return a random polynomial
     */
    public static IntegerPolynomial generateRandomPositive(int N, int q) {
        Random rng = new Random();
        int[] coeffs = new int[N];
        for (int i=0; i<N; i++)
            coeffs[i] = rng.nextInt(q);
        return new IntegerPolynomial(coeffs);
    }

    /**
     * Generates a polynomial with coefficients randomly selected from <code>{-1, 0, 1}</code>.
     * @param N number of coefficients
     */
    public static DenseTernaryPolynomial generateRandom(int N) {
        SecureRandom rng = new SecureRandom();
        int[] coeffs = new int[N];
        for (int i=0; i<N; i++)
            coeffs[i] = rng.nextInt(3) - 1;
        return new DenseTernaryPolynomial(coeffs);
    }
}