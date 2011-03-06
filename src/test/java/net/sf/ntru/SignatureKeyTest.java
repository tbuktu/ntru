package net.sf.ntru;

import org.junit.Test;
import static org.junit.Assert.assertArrayEquals;

public class SignatureKeyTest {
    
    @Test
    public void testEncode() {
        SignatureParameters params = SignatureParameters.T157;
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