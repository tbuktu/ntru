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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.junit.Test;

public class SignatureKeyTest {
    
    @Test
    public void testEncode() throws IOException {
        for (SignatureParameters params: new SignatureParameters[] {SignatureParameters.TEST157, SignatureParameters.TEST157_PROD})
            testEncode(params);
    }
    
    private void testEncode(SignatureParameters params) throws IOException {
        NtruSign ntru = new NtruSign(params);
        SignatureKeyPair kp = ntru.generateKeyPair();
        
        // encode to byte[] and reconstruct
        byte[] pub = kp.pub.getEncoded();
        byte[] priv = kp.priv.getEncoded();
        SignatureKeyPair kp2 = new SignatureKeyPair(new SignaturePrivateKey(priv), new SignaturePublicKey(pub));
        assertEquals(kp.pub, kp2.pub);
        assertEquals(kp.priv, kp2.priv);
        
        // encode to OutputStream and reconstruct
        ByteArrayOutputStream bos1 = new ByteArrayOutputStream();
        ByteArrayOutputStream bos2 = new ByteArrayOutputStream();
        kp.priv.writeTo(bos1);
        kp.pub.writeTo(bos2);
        ByteArrayInputStream bis1 = new ByteArrayInputStream(bos1.toByteArray());
        ByteArrayInputStream bis2 = new ByteArrayInputStream(bos2.toByteArray());
        SignatureKeyPair kp3 = new SignatureKeyPair(new SignaturePrivateKey(bis1), new SignaturePublicKey(bis2));
        assertEquals(kp.pub, kp3.pub);
        assertEquals(kp.priv, kp3.priv);
        assertNull(kp3.priv.getBasis(0).h);
    }
}