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

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.junit.Test;

public class EncryptionKeyTest {
    
    @Test
    public void testEncode() throws IOException {
        for (EncryptionParameters params: new EncryptionParameters[] {EncryptionParameters.APR2011_743, EncryptionParameters.APR2011_743_FAST, EncryptionParameters.EES1499EP1})
            testEncode(params);
    }
    
    private void testEncode(EncryptionParameters params) throws IOException {
        NtruEncrypt ntru = new NtruEncrypt(params);
        EncryptionKeyPair kp = ntru.generateKeyPair();
        byte[] priv = kp.priv.getEncoded();
        byte[] pub = kp.pub.getEncoded();
        EncryptionKeyPair kp2 = new EncryptionKeyPair(new EncryptionPrivateKey(priv), new EncryptionPublicKey(pub));
        assertEquals(kp.pub, kp2.pub);
        assertEquals(kp.priv, kp2.priv);
        
        ByteArrayOutputStream bos1 = new ByteArrayOutputStream();
        ByteArrayOutputStream bos2 = new ByteArrayOutputStream();
        kp.priv.writeTo(bos1);
        kp.pub.writeTo(bos2);
        ByteArrayInputStream bis1 = new ByteArrayInputStream(bos1.toByteArray());
        ByteArrayInputStream bis2 = new ByteArrayInputStream(bos2.toByteArray());
        EncryptionKeyPair kp3 = new EncryptionKeyPair(new EncryptionPrivateKey(bis1), new EncryptionPublicKey(bis2));
        assertEquals(kp.pub, kp3.pub);
        assertEquals(kp.priv, kp3.priv);
    }
}