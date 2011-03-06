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
        SignatureParameters params = SignatureParameters.T157;
        SignatureKeyPair kp = NtruSign.generateKeyPair(params);
        
        IntegerPolynomial i = new IntegerPolynomial(params.N);
        Random rng = new Random();
        for (int j=0; j<i.coeffs.length; j++)
            i.coeffs[j] = rng.nextInt(params.q) - params.q/2;
        
        // sign and verify
        IntegerPolynomial s = NtruSign.sign(i.clone(), kp.priv, kp.pub, params);
        boolean valid = NtruSign.verify(i.clone(), s, kp.pub.h.clone(), params);
        assertTrue(valid);

        // altering the signature should make it invalid
        for (int j=0; j<s.coeffs.length; j++)
            s.coeffs[rng.nextInt(params.N)] += 1;
        valid = NtruSign.verify(i, s, kp.pub.h, params);
        assertFalse(valid);

        // test that a random signature fails
        for (int j=0; j<s.coeffs.length; j++)
            s.coeffs[j] = rng.nextInt(params.q);
        valid = NtruSign.verify(i, s, kp.pub.h, params);
        assertFalse(valid);
        
        // encode, decode keypair, test
        SignaturePrivateKey priv = new SignaturePrivateKey(kp.priv.getEncoded(), params);
        SignaturePublicKey pub = new SignaturePublicKey(kp.pub.getEncoded(), params);
        kp = new SignatureKeyPair(priv, pub);
        s = NtruSign.sign(i, kp.priv, kp.pub, params);
        valid = NtruSign.verify(i, s, kp.pub.h, params);
        assertTrue(valid);
        
        // sign, verify text message
        byte[] msg = "test message".getBytes();
        byte[] s2 = NtruSign.sign(msg, kp.priv, kp.pub, params);
        valid = NtruSign.verify(msg, s2, kp.pub, params);
        assertTrue(valid);
        
        // altering the signature should make it invalid
        s2[rng.nextInt(s2.length)] += 1;
        valid = NtruSign.verify(msg, s2, kp.pub, params);
        assertFalse(valid);
        
        // decrease NormBound to force multiple signing attempts
        params.normBoundSq = Math.pow(70, 2);
        s2 = NtruSign.sign(msg, kp.priv, kp.pub, params);
        valid = NtruSign.verify(msg, s2, kp.pub, params);
        assertTrue(valid);
    }
    
    @Test
    public void testCreateMsgRep() throws NoSuchAlgorithmException {
        byte[] msg = "test message".getBytes();
        
        // verify that the message representative is reproducible
        IntegerPolynomial i1 = NtruSign.createMsgRep(msg, 1, SignatureParameters.T349);
        IntegerPolynomial i2 = NtruSign.createMsgRep(msg, 1, SignatureParameters.T349);
        assertArrayEquals(i1.coeffs, i2.coeffs);
        i1 = NtruSign.createMsgRep(msg, 5, SignatureParameters.T349);
        i2 = NtruSign.createMsgRep(msg, 5, SignatureParameters.T349);
        assertArrayEquals(i1.coeffs, i2.coeffs);
        
        i1 = NtruSign.createMsgRep(msg, 2, SignatureParameters.T349);
        i2 = NtruSign.createMsgRep(msg, 3, SignatureParameters.T349);
        assertFalse(Arrays.equals(i1.coeffs, i2.coeffs));
    }
}