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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import net.sf.ntru.polynomial.IntegerPolynomial;

/**
 * A NtruSign public key is essentially a polynomial named <code>h</code>.
 */
public class SignaturePublicKey {
    private SignatureParameters params;
    IntegerPolynomial h;

    /**
     * Constructs a new public key from a polynomial
     * @param h the polynomial <code>h</code> which determines the key
     * @param params the NtruSign parameters to use
     */
    SignaturePublicKey(IntegerPolynomial h, SignatureParameters params) {
        this.h = h;
        this.params = params;
    }
    
    /**
     * Converts a byte array to a polynomial <code>h</code> and constructs a new public key
     * @param b an encoded polynomial
     * @param params the NtruSign parameters to use
     */
    public SignaturePublicKey(byte[] b, SignatureParameters params) {
        h = IntegerPolynomial.fromBinary(b, params.N, params.q);
        this.params = params;
    }
    
    /**
     * Reads a polynomial <code>h</code> from an input stream and constructs a new public key
     * @param is an input stream
     * @param params the NtruSign parameters to use
     */
    public SignaturePublicKey(InputStream is, SignatureParameters params) throws IOException {
        h = IntegerPolynomial.fromBinary(is, params.N, params.q);
        this.params = params;
    }
    
    /**
     * Converts the key to a byte array
     * @return the encoded key
     */
    public byte[] getEncoded() {
        return h.toBinary(params.q);
    }
    
    /**
     * Writes the key to an output stream
     * @param os an output stream
     * @throws IOException
     */
    public void writeTo(OutputStream os) throws IOException {
        os.write(getEncoded());
    }
}