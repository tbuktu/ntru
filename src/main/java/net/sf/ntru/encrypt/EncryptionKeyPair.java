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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

import net.sf.ntru.arith.IntEuclidean;
import net.sf.ntru.encrypt.EncryptionParameters.TernaryPolynomialType;
import net.sf.ntru.polynomial.IntegerPolynomial;
import net.sf.ntru.polynomial.ProductFormPolynomial;

/** Contains a public and a private encryption key */
public class EncryptionKeyPair {
    EncryptionPrivateKey priv;
    EncryptionPublicKey pub;
    
    /**
     * Constructs a new key pair.
     * @param priv a private key
     * @param pub a public key
     */
    public EncryptionKeyPair(EncryptionPrivateKey priv, EncryptionPublicKey pub) {
        this.priv = priv;
        this.pub = pub;
    }
    
    /**
     * Constructs a new key pair from a byte array
     * @param b an encoded key pair
     */
    public EncryptionKeyPair(byte[] b) {
        ByteArrayInputStream is = new ByteArrayInputStream(b);
        pub = new EncryptionPublicKey(is);
        priv = new EncryptionPrivateKey(is);
    }
    
    /**
     * Constructs a new key pair from an input stream
     * @param is an input stream
     */
    public EncryptionKeyPair(InputStream is) {
        pub = new EncryptionPublicKey(is);
        priv = new EncryptionPrivateKey(is);
    }
    
    /**
     * Returns the private key
     * @return the private key
     */
    public EncryptionPrivateKey getPrivate() {
        return priv;
    }
    
    /**
     * Returns the public key
     * @return the public key
     */
    public EncryptionPublicKey getPublic() {
        return pub;
    }

    /**
     * Tests if the key pair is valid.<br/>
     * See IEEE 1363.1 section 9.2.4.1.
     * @return <code>true</code> if the key pair is valid, <code>false</code> otherwise
     */
    public boolean isValid() {
        int N = priv.N;
        int q = priv.q;
        TernaryPolynomialType polyType = priv.polyType;
        
        if (pub.N != N)
            return false;
        if (pub.q != q)
            return false;
        
        if (priv.t.toIntegerPolynomial().coeffs.length != N)
            return false;
        IntegerPolynomial h = pub.h.toIntegerPolynomial();
        if (h.coeffs.length != N)
            return false;
        
        if (!h.isReduced(q))
            return false;
        
        IntegerPolynomial f = priv.t.toIntegerPolynomial();
        if (polyType==TernaryPolynomialType.SIMPLE && !f.isTernary())
            return false;
        // if t is a ProductFormPolynomial, ternarity of f1,f2,f3 doesn't need to be verified
        if (polyType==TernaryPolynomialType.PRODUCT && !(priv.t instanceof ProductFormPolynomial))
            return false;
        
        if (polyType == TernaryPolynomialType.PRODUCT) {
            f.mult(3);
            f.coeffs[0] += 1;
            f.modPositive(q);
        }
        
        // the key generator pre-multiplies h by 3, so divide by 9 instead of 3
        int inv9 = IntEuclidean.calculate(9, q).x;   // 9^-1 mod q
        
        IntegerPolynomial g = f.mult(h, q);
        g.mult(inv9);
        g.modCenter(q);
        if (!g.isTernary())
            return false;
        int dg = N / 3;   // see EncryptionParameters.init()
        if (g.count(1) != dg)
            return false;
        if (g.count(-1) != dg-1)
            return false;
        return true;
    }
    
    /**
     * Converts the key pair to a byte array
     * @return the encoded key pair
     */
    public byte[] getEncoded() {
        byte[] pubArr = pub.getEncoded();
        byte[] privArr = priv.getEncoded();
        byte[] kpArr = Arrays.copyOf(pubArr, pubArr.length+privArr.length);
        System.arraycopy(privArr, 0, kpArr, pubArr.length, privArr.length);
        return kpArr;
    }
    
    /**
     * Writes the key pair to an output stream
     * @param os an output stream
     * @throws IOException
     */
    public void writeTo(OutputStream os) throws IOException {
        os.write(getEncoded());
    }
    
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((priv == null) ? 0 : priv.hashCode());
        result = prime * result + ((pub == null) ? 0 : pub.hashCode());
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
        EncryptionKeyPair other = (EncryptionKeyPair) obj;
        if (priv == null) {
            if (other.priv != null)
                return false;
        } else if (!priv.equals(other.priv))
            return false;
        if (pub == null) {
            if (other.pub != null)
                return false;
        } else if (!pub.equals(other.pub))
            return false;
        return true;
    }
}