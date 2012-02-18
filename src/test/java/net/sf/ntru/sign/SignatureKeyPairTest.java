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

import static net.sf.ntru.sign.SignatureParameters.TEST157;
import static net.sf.ntru.sign.SignatureParameters.TEST157_PROD;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import net.sf.ntru.arith.IntEuclidean;
import net.sf.ntru.polynomial.IntegerPolynomial;

import org.junit.Test;

public class SignatureKeyPairTest {
    
    @Test
    public void testIsValid() {
        // test valid key pairs
        NtruSign ntru = null;
        SignatureKeyPair kp = null;
        SignatureParameters[] paramSets = new SignatureParameters[] {TEST157, TEST157_PROD};
        for (SignatureParameters params: paramSets) {
            ntru = new NtruSign(params);
            kp = ntru.generateKeyPair();
            assertTrue(kp.isValid());
        }
        
        // test an invalid key pair
        SignatureParameters params = kp.pub.params;
        kp.pub.h.mult(101);   // make h invalid
        kp.pub.h.modPositive(params.q);
        assertFalse(kp.isValid());
        int inv101 = IntEuclidean.calculate(101, params.q).x;
        kp.pub.h.mult(inv101);   // restore h
        kp.pub.h.modPositive(params.q);
        IntegerPolynomial f = kp.priv.getBasis(0).f.toIntegerPolynomial();
        f.mult(3);   // make f invalid
        kp.priv.getBasis(0).f = f;
        assertFalse(kp.isValid());
    }
}