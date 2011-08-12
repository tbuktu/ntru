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

import net.sf.ntru.encrypt.EncryptionParameters.TernaryPolynomialType;
import net.sf.ntru.polynomial.IntegerPolynomial;
import net.sf.ntru.polynomial.Polynomial;
import net.sf.ntru.polynomial.ProductFormPolynomial;
import net.sf.ntru.polynomial.SparseTernaryPolynomial;

/**
 * A NtruEncrypt private key is essentially a polynomial named <code>f</code>.<br/>
 * The inverse of <code>f</code> modulo <code>p</code> is precomputed on initialization.
 */
public class EncryptionPrivateKey {
    private EncryptionParameters params;
    Polynomial t;
    IntegerPolynomial fp;

    /**
     * Constructs a new private key from a polynomial
     * @param t the polynomial which determines the key: if <code>fastFp=true</code>, <code>f=1+3t</code>; otherwise, <code>f=t</code>
     * @param fp the inverse of f
     * @param params the NtruEncrypt parameters to use
     */
    EncryptionPrivateKey(Polynomial t, IntegerPolynomial fp, EncryptionParameters params) {
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
        if (params.polyType == TernaryPolynomialType.PRODUCT) {
            int N = params.N;
            int df1 = params.df1;
            int df2 = params.df2;
            int df3Ones = params.df3;
            int df3NegOnes = params.fastFp ? params.df3 : params.df3-1;
//            fInt = ProductFormPolynomial.fromBinary(b, N, df1, df2, df3Ones, df3NegOnes);
            t = ProductFormPolynomial.fromBinary(b, N, df1, df2, df3Ones, df3NegOnes);
        }
        else {
            IntegerPolynomial fInt = IntegerPolynomial.fromBinary3Arith(b, params.N);
            t = new SparseTernaryPolynomial(fInt);
        }
        init();
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
        init();
    }
    
    /**
     * Initializes fp from t.
     */
    private void init() {
        if (params.fastFp) {
            fp = new IntegerPolynomial(params.N);
            fp.coeffs[0] = 1;
        }
        else
            fp = t.toIntegerPolynomial().invertF3();
    }
    
    /**
     * Converts the key to a byte array
     * @return the encoded key
     */
    public byte[] getEncoded() {
        if (t instanceof ProductFormPolynomial)
            return ((ProductFormPolynomial)t).toBinary();
        else
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