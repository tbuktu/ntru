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

import net.sf.ntru.exception.NtruException;
import net.sf.ntru.polynomial.IntegerPolynomial;
import net.sf.ntru.util.ArrayEncoder;

/**
 * A NtruEncrypt public key is essentially a polynomial named <code>h</code>.
 */
public class EncryptionPublicKey {
    int N;
    int q;
    IntegerPolynomial h;

    /**
     * Constructs a new public key from a polynomial
     * @param h the polynomial <code>h</code> which determines the key
     * @param N the number of coefficients in the polynomial <code>h</code>
     * @param q the "big" NtruEncrypt modulus
     */
    EncryptionPublicKey(IntegerPolynomial h, int N, int q) {
        this.h = h;
        this.N = N;
        this.q = q;
    }
    
    /**
     * Reconstructs a public key from its <code>byte</code> array representation.
     * @param b an encoded key
     * @see #getEncoded()
     */
    public EncryptionPublicKey(byte[] b) {
        this(new ByteArrayInputStream(b));
    }
    
    /**
     * Reconstructs a public key from its <code>byte</code> array representation.
     * @param is an input stream containing an encoded key
     * @throws NtruException if an {@link IOException} occurs
     * @see #writeTo(OutputStream)
     */
    public EncryptionPublicKey(InputStream is) {
        DataInputStream dataStream = new DataInputStream(is);
        try {
            N = dataStream.readShort();
            q = dataStream.readShort();
            h = IntegerPolynomial.fromBinary(dataStream, N, q);
        } catch (IOException e) {
            throw new NtruException(e);
        }
    }
    
    /**
     * Converts the key to a byte array
     * @return the encoded key
     * @see #EncryptionPublicKey(byte[])
     */
    public byte[] getEncoded() {
        return ArrayEncoder.concatenate(ArrayEncoder.toByteArray(N), ArrayEncoder.toByteArray(q), h.toBinary(q));
    }
    
    /**
     * Writes the key to an output stream
     * @param os an output stream
     * @throws IOException
     * @see #EncryptionPublicKey(InputStream)
     */
    public void writeTo(OutputStream os) throws IOException {
        os.write(getEncoded());
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + N;
        result = prime * result + ((h == null) ? 0 : h.hashCode());
        result = prime * result + q;
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
        EncryptionPublicKey other = (EncryptionPublicKey) obj;
        if (N != other.N)
            return false;
        if (h == null) {
            if (other.h != null)
                return false;
        } else if (!h.equals(other.h))
            return false;
        if (q != other.q)
            return false;
        return true;
    }
}