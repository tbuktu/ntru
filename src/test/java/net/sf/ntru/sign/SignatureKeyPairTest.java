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

import static net.sf.ntru.sign.SignatureParameters.TEST157;
import static net.sf.ntru.sign.SignatureParameters.TEST157_PROD;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

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
        int q = kp.pub.q;
        kp.pub.h.mult(101);   // make h invalid
        kp.pub.h.modPositive(q);
        assertFalse(kp.isValid());
        int inv101 = IntEuclidean.calculate(101, q).x;
        kp.pub.h.mult(inv101);   // restore h
        kp.pub.h.modPositive(q);
        IntegerPolynomial f = kp.priv.getBasis(0).f.toIntegerPolynomial();
        f.mult(3);   // make f invalid
        kp.priv.getBasis(0).f = f;
        assertFalse(kp.isValid());
    }
    
    @Test
    public void testEncode() throws IOException {
        SignatureParameters[] paramSets = new SignatureParameters[] {TEST157, TEST157_PROD};
        for (SignatureParameters params: paramSets)
            testEncode(params);
    }
    
    private void testEncode(SignatureParameters params) throws IOException {
        NtruSign ntru = new NtruSign(params);
        SignatureKeyPair kp = ntru.generateKeyPair();
        
        // encode to byte[] and reconstruct
        byte[] enc = kp.getEncoded();
        SignatureKeyPair kp2 = new SignatureKeyPair(enc);
        assertEquals(kp, kp2);
        
        // encode to OutputStream and reconstruct
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        kp.writeTo(bos);
        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        SignatureKeyPair kp3 = new SignatureKeyPair(bis);
        assertEquals(kp, kp3);
    }
}