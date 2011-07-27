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

package net.sf.ntru;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * A NtruEncrypt private key is essentially a polynomial named <code>f</code>.<br/>
 * The inverse of <code>f</code> modulo <code>p</code> is precomputed on initialization.
 */
public class EncryptionPrivateKey {
    private EncryptionParameters params;
    TernaryPolynomial t;
    IntegerPolynomial fp;

    /**
     * Constructs a new private key from a polynomial
     * @param t the polynomial which determines the key: if <code>fastFp=true</code>, <code>f=1+3t</code>; otherwise, <code>f=t</code>
     * @param fp the inverse of f
     * @param params the NtruEncrypt parameters to use
     */
    EncryptionPrivateKey(TernaryPolynomial t, IntegerPolynomial fp, EncryptionParameters params) {
        this.t = t;
        this.fp = fp;
        this.params = params;
    }
    
    /**
     * Converts a byte array to a polynomial <code>f</code> and constructs a new private key
     * @param b an encoded polynomial
     * @param params the NtruEncrypt parameters to use
     */
    public EncryptionPrivateKey(byte[] b, EncryptionParameters params) {
        this.params = params;
        IntegerPolynomial fInt = IntegerPolynomial.fromBinary3Arith(b, params.N);
        t = new SparseTernaryPolynomial(fInt);
        init(fInt);
    }
    
    /**
     * Reads a polynomial <code>f</code> from an input stream and constructs a new private key
     * @param is an input stream
     * @param params the NtruEncrypt parameters to use
     * @throws IOException
     */
    public EncryptionPrivateKey(InputStream is, EncryptionParameters params) throws IOException {
        this.params = params;
        IntegerPolynomial fInt = IntegerPolynomial.fromBinary3Arith(is, params.N);
        t = new SparseTernaryPolynomial(fInt);
        init(fInt);
    }
    
    /**
     * Initializes fp and t from fInt.
     */
    private void init(IntegerPolynomial fInt) {
        fInt.modCenter(params.q);
        t = new SparseTernaryPolynomial(fInt);
        if (params.fastFp) {
            fp = new IntegerPolynomial(params.N);
            fp.coeffs[0] = 1;
        }
        else
            fp = fInt.invertF3();
    }
    
    /**
     * Converts the key to a byte array
     * @return the encoded key
     */
    public byte[] getEncoded() {
        return t.toIntegerPolynomial().toBinary3Arith();
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