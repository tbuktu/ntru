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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import net.sf.ntru.polynomial.IntegerPolynomial;

/**
 * A NtruEncrypt public key is essentially a polynomial named <code>h</code>.
 */
public class EncryptionPublicKey {
    EncryptionParameters params;
    IntegerPolynomial h;

    /**
     * Constructs a new public key from a polynomial
     * @param h the polynomial <code>h</code> which determines the key
     * @param params the NtruEncrypt parameters to use
     */
    EncryptionPublicKey(IntegerPolynomial h, EncryptionParameters params) {
        this.h = h;
        this.params = params;
    }
    
    /**
     * Converts a byte array to a polynomial <code>h</code> and constructs a new public key
     * @param b an encoded polynomial
     * @param params the NtruEncrypt parameters to use
     * @see #getEncoded()
     */
    public EncryptionPublicKey(byte[] b, EncryptionParameters params) {
        this.params = params;
        h = IntegerPolynomial.fromBinary(b, params.N, params.q);
    }
    
    /**
     * Reads a polynomial <code>h</code> from an input stream and constructs a new public key
     * @param is an input stream
     * @param params the NtruEncrypt parameters to use
     * @throws IOException
     * @see #writeTo(OutputStream)
     */
    public EncryptionPublicKey(InputStream is, EncryptionParameters params) throws IOException {
        this.params = params;
        h = IntegerPolynomial.fromBinary(is, params.N, params.q);
    }
    
    /**
     * Converts the key to a byte array
     * @return the encoded key
     * @see #EncryptionPublicKey(byte[], EncryptionParameters)
     */
    public byte[] getEncoded() {
        return h.toBinary(params.q);
    }
    
    /**
     * Writes the key to an output stream
     * @param os an output stream
     * @throws IOException
     * @see #EncryptionPublicKey(InputStream, EncryptionParameters)
     */
    public void writeTo(OutputStream os) throws IOException {
        os.write(getEncoded());
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((h == null) ? 0 : h.hashCode());
        result = prime * result + ((params == null) ? 0 : params.hashCode());
        return result;
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (!(obj instanceof EncryptionPublicKey))
            return false;
        EncryptionPublicKey other = (EncryptionPublicKey) obj;
        if (h == null) {
            if (other.h != null)
                return false;
        } else if (!h.equals(other.h))
            return false;
        if (params == null) {
            if (other.params != null)
                return false;
        } else if (!params.equals(other.params))
            return false;
        return true;
    }
}