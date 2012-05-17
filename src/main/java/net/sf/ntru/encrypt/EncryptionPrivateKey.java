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

package net.sf.ntru.encrypt;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import net.sf.ntru.encrypt.EncryptionParameters.TernaryPolynomialType;
import net.sf.ntru.exception.NtruException;
import net.sf.ntru.polynomial.DenseTernaryPolynomial;
import net.sf.ntru.polynomial.IntegerPolynomial;
import net.sf.ntru.polynomial.Polynomial;
import net.sf.ntru.polynomial.ProductFormPolynomial;
import net.sf.ntru.polynomial.SparseTernaryPolynomial;
import net.sf.ntru.util.ArrayEncoder;

/**
 * A NtruEncrypt private key is essentially a polynomial named <code>f</code>
 * which takes different forms depending on whether product-form polynomials are used,
 * and on <code>fastP</code><br/>
 * The inverse of <code>f</code> modulo <code>p</code> is precomputed on initialization.
 */
public class EncryptionPrivateKey {
    int N;
    int q;
    TernaryPolynomialType polyType;
    private boolean sparse;
    private boolean fastFp;
    Polynomial t;
    IntegerPolynomial fp;

    /**
     * Constructs a new private key from a polynomial
     * @param t the polynomial which determines the key: if <code>fastFp=true</code>, <code>f=1+3t</code>; otherwise, <code>f=t</code>
     * @param fp the inverse of <code>f</code>
     * @param N the number of polynomial coefficients
     * @param q the "big" NtruEncrypt modulus
     * @param sparse whether the polynomial <code>t</code> is sparsely or densely populated
     * @param fastFp whether <code>fp=1</code>
     * @param polyType type of the polynomial <code>t</code>
     */
    EncryptionPrivateKey(Polynomial t, IntegerPolynomial fp, int N, int q, boolean sparse, boolean fastFp, TernaryPolynomialType polyType) {
        this.t = t;
        this.fp = fp;
        this.N = N;
        this.q = q;
        this.sparse = sparse;
        this.fastFp = fastFp;
        this.polyType = polyType;
    }
    
    /**
     * Converts a byte array to a polynomial <code>f</code> and constructs a new private key
     * @param b an encoded polynomial
     * @see #getEncoded()
     */
    public EncryptionPrivateKey(byte[] b) {
        this(new ByteArrayInputStream(b));
    }
    
    /**
     * Reads a polynomial <code>f</code> from an input stream and constructs a new private key
     * @param is an input stream
     * @throws NtruException if an {@link IOException} occurs
     * @see #writeTo(OutputStream)
     */
    public EncryptionPrivateKey(InputStream is) {
        DataInputStream dataStream = new DataInputStream(is);
        try {
            N = dataStream.readShort();
            q = dataStream.readShort();
            byte flags = dataStream.readByte();
            sparse = (flags&1) != 0;
            fastFp = (flags&2) != 0;
            polyType = (flags&4)==0 ? TernaryPolynomialType.SIMPLE : TernaryPolynomialType.PRODUCT;
            if (polyType == TernaryPolynomialType.PRODUCT) {
                t = ProductFormPolynomial.fromBinary(dataStream, N);
            }
            else {
                IntegerPolynomial fInt = IntegerPolynomial.fromBinary3Tight(dataStream, N);
                t = sparse ? new SparseTernaryPolynomial(fInt) : new DenseTernaryPolynomial(fInt);
            }
        }
        catch (IOException e) {
            throw new NtruException(e);
        }
        init();
    }
    
    /**
     * Initializes <code>fp</code> from t.
     */
    private void init() {
        if (fastFp) {
            fp = new IntegerPolynomial(N);
            fp.coeffs[0] = 1;
        }
        else
            fp = t.toIntegerPolynomial().invertF3();
    }
    
    /**
     * Converts the key to a byte array
     * @return the encoded key
     * @see #EncryptionPrivateKey(byte[])
     */
    public byte[] getEncoded() {
        int flags = (sparse?1:0) + (fastFp?2:0) + (polyType==TernaryPolynomialType.PRODUCT?4:0);
        byte[] flagsByte = new byte[] {(byte)flags};
        
        byte[] tBin;
        if (t instanceof ProductFormPolynomial)
            tBin = ((ProductFormPolynomial)t).toBinary();
        else
            tBin = t.toIntegerPolynomial().toBinary3Tight();
        
        return ArrayEncoder.concatenate(ArrayEncoder.toByteArray(N), ArrayEncoder.toByteArray(q), flagsByte, tBin);
    }
    
    /**
     * Writes the key to an output stream
     * @param os an output stream
     * @throws IOException
     * @see #EncryptionPrivateKey(InputStream)
     */
    public void writeTo(OutputStream os) throws IOException {
        os.write(getEncoded());
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + N;
        result = prime * result + (fastFp ? 1231 : 1237);
        result = prime * result + ((fp == null) ? 0 : fp.hashCode());
        result = prime * result
                + ((polyType == null) ? 0 : polyType.hashCode());
        result = prime * result + q;
        result = prime * result + (sparse ? 1231 : 1237);
        result = prime * result + ((t == null) ? 0 : t.hashCode());
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
        EncryptionPrivateKey other = (EncryptionPrivateKey) obj;
        if (N != other.N)
            return false;
        if (fastFp != other.fastFp)
            return false;
        if (fp == null) {
            if (other.fp != null)
                return false;
        } else if (!fp.equals(other.fp))
            return false;
        if (polyType != other.polyType)
            return false;
        if (q != other.q)
            return false;
        if (sparse != other.sparse)
            return false;
        if (t == null) {
            if (other.t != null)
                return false;
        } else if (!t.equals(other.t))
            return false;
        return true;
    }
}