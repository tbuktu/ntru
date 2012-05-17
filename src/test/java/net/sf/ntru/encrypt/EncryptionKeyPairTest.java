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
        EncryptionKeyPair kp2 = new EncryptionKeyPair(enc);
        assertEquals(kp, kp2);
        
        // encode to OutputStream and reconstruct
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        kp.writeTo(bos);
        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        EncryptionKeyPair kp3 = new EncryptionKeyPair(bis);
        assertEquals(kp, kp3);
    }
}