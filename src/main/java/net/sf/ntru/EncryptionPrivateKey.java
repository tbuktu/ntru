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

public class EncryptionPrivateKey {
    private EncryptionParameters params;
    TernaryPolynomial f;
    IntegerPolynomial fp;

    EncryptionPrivateKey(TernaryPolynomial f, EncryptionParameters params) {
        this.f = f;
        this.params = params;
        fp = f.toIntegerPolynomial().invertF3();
    }
    
    public EncryptionPrivateKey(byte[] b, EncryptionParameters params) {
        this.params = params;
        IntegerPolynomial fInt = IntegerPolynomial.fromBinary3Arith(b, params.N);
        init(fInt);
    }
    
    public EncryptionPrivateKey(InputStream is, EncryptionParameters params) throws IOException {
        this.params = params;
        IntegerPolynomial fInt = IntegerPolynomial.fromBinary3Arith(is, params.N);
        init(fInt);
    }
    
    private void init(IntegerPolynomial fInt) {
        fInt.modCenter(params.q);
        fp = fInt.invertF3();
        f = new SparseTernaryPolynomial(fInt);
    }
    
    public byte[] getEncoded() {
        return f.toIntegerPolynomial().toBinary3Arith();
    }
    
    public void writeTo(OutputStream os) throws IOException {
        os.write(getEncoded());
    }
}