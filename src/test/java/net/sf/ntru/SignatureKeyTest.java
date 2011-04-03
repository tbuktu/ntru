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

import org.junit.Test;
import static org.junit.Assert.assertArrayEquals;

public class SignatureKeyTest {
    
    @Test
    public void testEncode() {
        SignatureParameters params = SignatureParameters.TEST157;
        SignatureKeyPair kp = NtruSign.generateKeyPair(params);
        byte[] priv = kp.priv.getEncoded();
        byte[] pub = kp.pub.getEncoded();
        SignatureKeyPair kp2 = new SignatureKeyPair(new SignaturePrivateKey(priv, params), new SignaturePublicKey(pub, params));
        byte[] priv2 = kp2.priv.getEncoded();
        assertArrayEquals(priv, priv2);
        byte[] pub2 = kp2.pub.getEncoded();
        assertArrayEquals(pub, pub2);
    }
}