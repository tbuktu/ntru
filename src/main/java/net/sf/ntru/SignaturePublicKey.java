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

public class SignaturePublicKey {
    private SignatureParameters params;
    IntegerPolynomial h;

    SignaturePublicKey(IntegerPolynomial h, SignatureParameters params) {
        this.h = h;
        this.params = params;
    }
    
    public SignaturePublicKey(byte[] b, SignatureParameters params) {
        h = IntegerPolynomial.fromBinary(b, params.N, params.q);
        this.params = params;
    }
    
    public byte[] getEncoded() {
        return h.toBinary(params.q);
    }
}