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