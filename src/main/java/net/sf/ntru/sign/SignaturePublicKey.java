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

package net.sf.ntru.sign;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import net.sf.ntru.exception.NtruException;
import net.sf.ntru.polynomial.IntegerPolynomial;

/**
 * A NtruSign public key is essentially a polynomial named <code>h</code>.
 */
public class SignaturePublicKey {
    IntegerPolynomial h;
    int q;

    /**
     * Constructs a new public key from a polynomial
     * @param h the polynomial <code>h</code> which determines the key
     * @param q the modulus
     */
    SignaturePublicKey(IntegerPolynomial h, int q) {
        this.h = h;
        this.q = q;
    }
    
    /**
     * Reconstructs a public key from its <code>byte</code> array representation.
     * @param b an encoded key
     * @see #getEncoded()
     */
    public SignaturePublicKey(byte[] b) {
        this(new ByteArrayInputStream(b));
    }
    
    /**
     * Reconstructs a public key from its <code>byte</code> array representation.
     * @param is an input stream containing an encoded key
     * @throws NtruException if an {@link IOException} occurs
     * @see #writeTo(OutputStream)
     */
    public SignaturePublicKey(InputStream is) {
        DataInputStream dataStream = new DataInputStream(is);
        try {
            int N = dataStream.readShort();
            q = dataStream.readShort();
            h = IntegerPolynomial.fromBinary(dataStream, N, q);
        } catch (IOException e) {
            throw new NtruException(e);
        }
    }
    
    /**
     * Converts the key to a byte array
     * @return the encoded key
     * @see #SignaturePublicKey(byte[])
     */
    public byte[] getEncoded() {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(os);
        try {
            dataStream.writeShort(h.coeffs.length);
            dataStream.writeShort(q);
            dataStream.write(h.toBinary(q));
        } catch (IOException e) {
            throw new NtruException(e);
        }
        return os.toByteArray();
    }
    
    /**
     * Writes the key to an output stream
     * @param os an output stream
     * @throws IOException
     * @see #SignaturePublicKey(InputStream)
     */
    public void writeTo(OutputStream os) throws IOException {
        os.write(getEncoded());
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
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
        SignaturePublicKey other = (SignaturePublicKey) obj;
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