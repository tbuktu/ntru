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

import static net.sf.ntru.encrypt.EncryptionParameters.APR2011_439;
import static net.sf.ntru.encrypt.EncryptionParameters.APR2011_439_FAST;
import static net.sf.ntru.encrypt.EncryptionParameters.APR2011_743_FAST;
import static net.sf.ntru.encrypt.EncryptionParameters.EES1087EP2;
import static net.sf.ntru.encrypt.EncryptionParameters.EES1499EP1;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import net.sf.ntru.polynomial.IntegerPolynomial;

import org.junit.Test;

public class EncryptionKeyPairTest {
    
    @Test
    public void testIsValid() {
        // test valid key pairs
        EncryptionParameters[] paramSets = new EncryptionParameters[] {
                APR2011_439, APR2011_439_FAST, APR2011_743_FAST, EES1087EP2, EES1499EP1};
        for (EncryptionParameters params: paramSets) {
            NtruEncrypt ntru = new NtruEncrypt(params);
            EncryptionKeyPair kp = ntru.generateKeyPair();
            assertTrue(kp.isValid());
        }
        
        // test an invalid key pair
        EncryptionParameters params = APR2011_439;
        NtruEncrypt ntru = new NtruEncrypt(params);
        EncryptionKeyPair kp = ntru.generateKeyPair();
        kp.pub.h.coeffs[55]++;
        assertFalse(kp.isValid());
        kp.pub.h.coeffs[55]--;
        IntegerPolynomial t = kp.priv.t.toIntegerPolynomial();
        t.coeffs[66]++;
        kp.priv.t = t;
        assertFalse(kp.isValid());
    }
    
    @Test
    public void testEncode() throws IOException {
        EncryptionParameters[] paramSets = new EncryptionParameters[] {APR2011_439, APR2011_439_FAST, APR2011_743_FAST, EES1087EP2, EES1499EP1};
        for (EncryptionParameters params: paramSets)
            testEncode(params);
    }
    
    private void testEncode(EncryptionParameters params) throws IOException {
        NtruEncrypt ntru = new NtruEncrypt(params);
        EncryptionKeyPair kp = ntru.generateKeyPair();
        
        // encode to byte[] and reconstruct
        byte[] enc = kp.getEncoded();
        EncryptionKeyPair kp2 = new EncryptionKeyPair(enc, params);
        assertEquals(kp, kp2);
        
        // encode to OutputStream and reconstruct
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        kp.writeTo(bos);
        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        EncryptionKeyPair kp3 = new EncryptionKeyPair(bis, params);
        assertEquals(kp, kp3);
    }
}