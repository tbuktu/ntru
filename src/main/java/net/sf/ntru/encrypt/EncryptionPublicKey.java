/**
 * This software is dual-licensed. You may choose either the
 * Non-Profit Open Software License version 3.0, or any license
 * agreement into which you enter with Security Innovation, Inc.
 * 
 * Use of this code, or certain portions thereof, implements
 * inventions covered by claims of one or more of the following
 * U.S. Patents and/or foreign counterpart patents, owned by
 * Security Innovation, Inc.:
 * 7,308,097, 7,031,468, 6,959,085, 6,298,137, and 6,081,597.
 * Practice or sale of the inventions embodied in the code hereof
 * requires a license from Security Innovation Inc. at:
 * 
 * 187 Ballardvale St, Suite A195
 * Wilmington, MA 01887
 * USA
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