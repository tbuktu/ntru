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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

import org.junit.Test;

public class NtruSignTest {
    
    @Test
    public void testSignVerify() {
        SignatureParameters params = SignatureParameters.TEST157;
        SignatureKeyPair kp = NtruSign.generateKeyPair(params);
        
        Random rng = new Random();
        byte[] msg = new byte[10+rng.nextInt(1000)];
        rng.nextBytes(msg);
        
        // sign and verify
        byte[] s = NtruSign.sign(msg, kp.priv, kp.pub, params);
        boolean valid = NtruSign.verify(msg, s, kp.pub, params);
        assertTrue(valid);
        
        // altering the signature should make it invalid
        s[rng.nextInt(params.N)] += 1;
        valid = NtruSign.verify(msg, s, kp.pub, params);
        assertFalse(valid);

        // test that a random signature fails
        rng.nextBytes(s);
        valid = NtruSign.verify(msg, s, kp.pub, params);
        assertFalse(valid);
        
        // encode, decode keypair, test
        SignaturePrivateKey priv = new SignaturePrivateKey(kp.priv.getEncoded(), params);
        SignaturePublicKey pub = new SignaturePublicKey(kp.pub.getEncoded(), params);
        kp = new SignatureKeyPair(priv, pub);
        s = NtruSign.sign(msg, kp.priv, kp.pub, params);
        valid = NtruSign.verify(msg, s, kp.pub, params);
        assertTrue(valid);
        
        // altering the signature should make it invalid
        s[rng.nextInt(s.length)] += 1;
        valid = NtruSign.verify(msg, s, kp.pub, params);
        assertFalse(valid);
        
        // decrease NormBound to force multiple signing attempts
        params.normBoundSq = Math.pow(45, 2);
//        params.normBoundSq = Math.pow(183, 2);
//        params.normBoundSq = Math.pow(320, 2);
        s = NtruSign.sign(msg, kp.priv, kp.pub, params);
        valid = NtruSign.verify(msg, s, kp.pub, params);
        assertTrue(valid);
    }
    
    @Test
    public void testCreateMsgRep() throws NoSuchAlgorithmException {
        byte[] msg = "test message".getBytes();
        
        // verify that the message representative is reproducible
        IntegerPolynomial i1 = NtruSign.createMsgRep(msg, 1, SignatureParameters.TEST157);
        IntegerPolynomial i2 = NtruSign.createMsgRep(msg, 1, SignatureParameters.TEST157);
        assertArrayEquals(i1.coeffs, i2.coeffs);
        i1 = NtruSign.createMsgRep(msg, 5, SignatureParameters.TEST157);
        i2 = NtruSign.createMsgRep(msg, 5, SignatureParameters.TEST157);
        assertArrayEquals(i1.coeffs, i2.coeffs);
        
        i1 = NtruSign.createMsgRep(msg, 2, SignatureParameters.TEST157);
        i2 = NtruSign.createMsgRep(msg, 3, SignatureParameters.TEST157);
        assertFalse(Arrays.equals(i1.coeffs, i2.coeffs));
    }
}