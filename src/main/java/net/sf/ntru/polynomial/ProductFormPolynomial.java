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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Random;

import net.sf.ntru.exception.NtruException;

/**
 * A polynomial of the form <code>f1*f2+f3</code>, where
 * <code>f1,f2,f3</code> are very sparsely populated ternary polynomials.
 */
public class ProductFormPolynomial implements Polynomial {
    private SparseTernaryPolynomial f1, f2, f3;
    
    /**
     * Constructs a new polynomial from three sparsely populated ternary polynomials.
     * @param f1
     * @param f2
     * @param f3
     */
    public ProductFormPolynomial(SparseTernaryPolynomial f1, SparseTernaryPolynomial f2, SparseTernaryPolynomial f3) {
        this.f1 = f1;
        this.f2 = f2;
        this.f3 = f3;
    }
    
    /**
     * Generates a <code>ProductFormPolynomial</code> from three random ternary polynomials.
     * @param N number of coefficients
     * @param df1 number of ones in the first polynomial; also the number of negative ones
     * @param df2 number of ones in the second polynomial; also the number of negative ones
     * @param df3Ones number of ones in the third polynomial
     * @param df3NegOnes number of negative ones in the third polynomial
     * @param rng a random number generator
     * @return a random <code>ProductFormPolynomial</code>
     */
    public static ProductFormPolynomial generateRandom(int N, int df1, int df2, int df3Ones, int df3NegOnes, Random rng) {
        SparseTernaryPolynomial f1 = SparseTernaryPolynomial.generateRandom(N, df1, df1, rng);
        SparseTernaryPolynomial f2 = SparseTernaryPolynomial.generateRandom(N, df2, df2, rng);
        SparseTernaryPolynomial f3 = SparseTernaryPolynomial.generateRandom(N, df3Ones, df3NegOnes, rng);
        return new ProductFormPolynomial(f1, f2, f3);
    }
    
    /**
     * Decodes a byte array encoded with {@link #toBinary()} to a polynomial.
     * @param data an encoded <code>ProductFormPolynomial</code>
     * @param N number of coefficients in the polynomial
     * @return the decoded polynomial
     */
    public static ProductFormPolynomial fromBinary(byte[] data, int N) {
        return fromBinary(new ByteArrayInputStream(data), N);
    }
    
    /**
     * Decodes a polynomial encoded with {@link #toBinary()}.
     * @param is an input stream containing an encoded polynomial
     * @param N number of coefficients in the polynomial
     * @return the decoded polynomial
     */
    public static ProductFormPolynomial fromBinary(InputStream is, int N) {
        SparseTernaryPolynomial f1;
        try {
            f1 = SparseTernaryPolynomial.fromBinary(is, N);
            SparseTernaryPolynomial f2 = SparseTernaryPolynomial.fromBinary(is, N);
            SparseTernaryPolynomial f3 = SparseTernaryPolynomial.fromBinary(is, N);
            return new ProductFormPolynomial(f1, f2, f3);
        } catch (IOException e) {
            throw new NtruException(e);
        }
    }
    
    /**
     * Encodes the polynomial to a byte array.
     * @return the encoded polynomial
     */
    public byte[] toBinary() {
        byte[] f1Bin = f1.toBinary();
        byte[] f2Bin = f2.toBinary();
        byte[] f3Bin = f3.toBinary();
        
        byte[] all = Arrays.copyOf(f1Bin, f1Bin.length + f2Bin.length + f3Bin.length);
        System.arraycopy(f2Bin, 0, all, f1Bin.length, f2Bin.length);
        System.arraycopy(f3Bin, 0, all, f1Bin.length+f2Bin.length, f3Bin.length);
        return all;
    }
    
    @Override
    public IntegerPolynomial mult(IntegerPolynomial b) {
        IntegerPolynomial c = f1.mult(b);
        c = f2.mult(c);
        c.add(f3.mult(b));
        return c;
    }

    @Override
    public IntegerPolynomial mult(IntegerPolynomial poly2, int modulus) {
        IntegerPolynomial c = mult(poly2);
        c.mod(modulus);
        return c;
    }

    @Override
    public BigIntPolynomial mult(BigIntPolynomial b) {
        BigIntPolynomial c = f1.mult(b);
        c = f2.mult(c);
        c.add(f3.mult(b));
        return c;
    }

    @Override
    public IntegerPolynomial toIntegerPolynomial() {
        IntegerPolynomial i = f1.mult(f2.toIntegerPolynomial());
        i.add(f3);
        return i;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((f1 == null) ? 0 : f1.hashCode());
        result = prime * result + ((f2 == null) ? 0 : f2.hashCode());
        result = prime * result + ((f3 == null) ? 0 : f3.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        ProductFormPolynomial other = (ProductFormPolynomial) obj;
        if (f1 == null) {
            if (other.f1 != null)
                return false;
        } else if (!f1.equals(other.f1))
            return false;
        if (f2 == null) {
            if (other.f2 != null)
                return false;
        } else if (!f2.equals(other.f2))
            return false;
        if (f3 == null) {
            if (other.f3 != null)
                return false;
        } else if (!f3.equals(other.f3))
            return false;
        return true;
    }
}