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

public class EncryptionPublicKey {
    private EncryptionParameters params;
    IntegerPolynomial h;

    EncryptionPublicKey(IntegerPolynomial h, EncryptionParameters params) {
        this.h = h;
        this.params = params;
    }
    
    public EncryptionPublicKey(byte[] b, EncryptionParameters params) {
        this.params = params;
        h = IntegerPolynomial.fromBinary(b, params.N, params.q);
    }
    
    public EncryptionPublicKey(InputStream is, EncryptionParameters params) throws IOException {
        this.params = params;
        h = IntegerPolynomial.fromBinary(is, params.N, params.q);
    }
    
    public byte[] getEncoded() {
        return h.toBinary(params.q);
    }
    
    public void writeTo(OutputStream os) throws IOException {
        os.write(getEncoded());
    }
}