/**
 * Copyright (c) 2011, Tim Buktu
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package net.sf.ntru.sign;

import static net.sf.ntru.sign.SignatureParameters.APR2011_439_PROD;
import static net.sf.ntru.sign.SignatureParameters.TEST157;
import static net.sf.ntru.sign.SignatureParameters.TEST157_PROD;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Random;

import net.sf.ntru.polynomial.IntegerPolynomial;
import net.sf.ntru.polynomial.Polynomial;
import net.sf.ntru.sign.NtruSign.FGBasis;
import net.sf.ntru.sign.SignatureParameters.KeyGenAlg;

import org.junit.Test;

public class NtruSignTest {
    
    @Test
    public void testCreateBasis() {
        for (SignatureParameters params: new SignatureParameters[] {TEST157.clone(), TEST157_PROD.clone()})
            testCreateBasis(params);
    }
    
    private void testCreateBasis(SignatureParameters params) {
        NtruSign ntru = new NtruSign(params);
        FGBasis basis = (FGBasis)ntru.generateBoundedBasis();
        assertTrue(equalsQ(basis.f, basis.fPrime, basis.F, basis.G, params.q, params.N));
        
        // test KeyGenAlg.FLOAT (default=RESULTANT)
        params.keyGenAlg = KeyGenAlg.FLOAT;
        ntru = new NtruSign(params);
        basis = (FGBasis)ntru.generateBoundedBasis();
        assertTrue(equalsQ(basis.f, basis.fPrime, basis.F, basis.G, params.q, params.N));
    }
    
    // verifies that f*G-g*F=q
    private boolean equalsQ(Polynomial f, Polynomial g, IntegerPolynomial F, IntegerPolynomial G, int q, int N) {
        IntegerPolynomial x = f.mult(G);
        x.sub(g.mult(F));
        boolean equalsQ=true;
        for (int i=1; i<x.coeffs.length; i++)
            equalsQ &= x.coeffs[i] == 0;
        equalsQ &= x.coeffs[0] == q;
        return equalsQ;
    }
    
    /** a test for the one-method-call variants: sign(byte, SignatureKeyPair) and verify(byte[], byte[], SignatureKeyPair) */
    @Test
    public void testSignVerify() {
        for (SignatureParameters params: new SignatureParameters[] {TEST157.clone(), TEST157_PROD.clone()})
            testSignVerify(params);
    }
    
    private void testSignVerify(SignatureParameters params) {
        NtruSign ntru = new NtruSign(params);
        
        SignatureKeyPair kp = ntru.generateKeyPair();
        
        assertEquals(params.B+1, kp.priv.getNumBases());
        
        Random rng = new Random();
        byte[] msg = new byte[10+rng.nextInt(1000)];
        rng.nextBytes(msg);
        
        // sign and verify
        byte[] s = ntru.sign(msg, kp);
        boolean valid = ntru.verify(msg, s, kp.pub);
        assertTrue(valid);
        
        // altering the signature should make it invalid
        s[rng.nextInt(params.N)] += 1;
        valid = ntru.verify(msg, s, kp.pub);
        assertFalse(valid);

        // test that a random signature fails
        rng.nextBytes(s);
        valid = ntru.verify(msg, s, kp.pub);
        assertFalse(valid);
        
        // encode, decode keypair, test
        SignaturePrivateKey priv = new SignaturePrivateKey(kp.priv.getEncoded());
        SignaturePublicKey pub = new SignaturePublicKey(kp.pub.getEncoded());
        kp = new SignatureKeyPair(priv, pub);
        s = ntru.sign(msg, kp);
        valid = ntru.verify(msg, s, kp.pub);
        assertTrue(valid);
        
        // altering the signature should make it invalid
        s[rng.nextInt(s.length)] += 1;
        valid = ntru.verify(msg, s, kp.pub);
        assertFalse(valid);
        
        // sparse/dense
        params.sparse = !params.sparse;
        s = ntru.sign(msg, kp);
        valid = ntru.verify(msg, s, kp.pub);
        assertTrue(valid);
        s[rng.nextInt(s.length)] += 1;
        valid = ntru.verify(msg, s, kp.pub);
        assertFalse(valid);
        params.sparse = !params.sparse;
        
        // decrease NormBound to force multiple signing attempts
        SignatureParameters params2 = params.clone();
        params2.normBoundSq *= 4.0 / 9;   // works for APR2011_439_PROD but may need to be increased for different params
        params2.signFailTolerance = 10000;
        ntru = new NtruSign(params2);
        s = ntru.sign(msg, kp);
        valid = ntru.verify(msg, s, kp.pub);
        assertTrue(valid);
        
        // test KeyGenAlg.FLOAT (default=RESULTANT)
        params2 = params.clone();
        params.keyGenAlg = KeyGenAlg.FLOAT;
        ntru = new NtruSign(params);
        kp = ntru.generateKeyPair();
        s = ntru.sign(msg, kp);
        valid = ntru.verify(msg, s, kp.pub);
        assertTrue(valid);
        s[rng.nextInt(s.length)] += 1;
        valid = ntru.verify(msg, s, kp.pub);
        assertFalse(valid);
    }
    
    /** test for the initSign/update/sign and initVerify/update/verify variant */
    @Test
    public void testInitUpdateSign() {
        for (SignatureParameters params: new SignatureParameters[] {TEST157.clone(), TEST157_PROD.clone()})
            testInitUpdateSign(params);
    }
    
    private void testInitUpdateSign(SignatureParameters params) {
        NtruSign ntru = new NtruSign(params);
        
        SignatureKeyPair kp = ntru.generateKeyPair();
        
        Random rng = new Random();
        byte[] msg = new byte[10+rng.nextInt(1000)];
        rng.nextBytes(msg);
        
        // sign and verify a message in two pieces each
        ntru.initSign(kp);
        int splitIdx = rng.nextInt(msg.length);
        ntru.update(Arrays.copyOf(msg, splitIdx));   // part 1 of msg
        byte[] s = ntru.sign(Arrays.copyOfRange(msg, splitIdx, msg.length));   // part 2 of msg
        ntru.initVerify(kp.pub);
        splitIdx = rng.nextInt(msg.length);
        ntru.update(Arrays.copyOf(msg, splitIdx));   // part 1 of msg
        ntru.update(Arrays.copyOfRange(msg, splitIdx, msg.length));   // part 2 of msg
        boolean valid = ntru.verify(s);
        assertTrue(valid);
        // verify the same signature with the one-step method
        valid = ntru.verify(msg, s, kp.pub);
        assertTrue(valid);
        
        // sign using the one-step method and verify using the multi-step method
        s = ntru.sign(msg, kp);
        ntru.initVerify(kp.pub);
        splitIdx = rng.nextInt(msg.length);
        ntru.update(Arrays.copyOf(msg, splitIdx));   // part 1 of msg
        ntru.update(Arrays.copyOfRange(msg, splitIdx, msg.length));   // part 2 of msg
        valid = ntru.verify(s);
        assertTrue(valid);
    }
    
    @Test
    public void testCreateMsgRep() {
        for (SignatureParameters params: new SignatureParameters[] {TEST157.clone(), TEST157_PROD.clone()})
            testCreateMsgRep(params);
    }
    
    private void testCreateMsgRep(SignatureParameters params) {
        NtruSign ntru = new NtruSign(params);
        byte[] msgHash = "adfsadfsdfs23234234".getBytes();
        
        // verify that the message representative is reproducible
        IntegerPolynomial i1 = ntru.createMsgRep(msgHash, 1);
        IntegerPolynomial i2 = ntru.createMsgRep(msgHash, 1);
        assertArrayEquals(i1.coeffs, i2.coeffs);
        i1 = ntru.createMsgRep(msgHash, 5);
        i2 = ntru.createMsgRep(msgHash, 5);
        assertArrayEquals(i1.coeffs, i2.coeffs);
        
        i1 = ntru.createMsgRep(msgHash, 2);
        i2 = ntru.createMsgRep(msgHash, 3);
        assertFalse(Arrays.equals(i1.coeffs, i2.coeffs));
    }
    
    @Test
    public void testGetOutputLength() {
        SignatureParameters[] paramSets = new SignatureParameters[] {TEST157, TEST157_PROD, APR2011_439_PROD};
        byte[] msg = "test message 12345".getBytes();
        
        for (SignatureParameters params: paramSets) {
            NtruSign ntru = new NtruSign(params);
            SignatureKeyPair kp = ntru.generateKeyPair();
            byte[] s = ntru.sign(msg, kp);
            assertEquals(params.getOutputLength(), s.length);
        }
    }
}