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

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Benchmark {
    private byte[] plain = "test message".getBytes();
    
    private void run() throws NoSuchAlgorithmException {
        long minEncTime = Long.MAX_VALUE;
        long minSigTime = Long.MAX_VALUE;
        long totEncTime = 0;
        long totSigTime = 0;
        int iterations = 5;
        
        for (int i=0; i<iterations; i++) {
            long encTime = encBench();
            long sigTime = signBench();
            System.out.println("NTRUEncrypt " + encTime + "ms\tNTRUSign " + sigTime + "ms");
            
            minEncTime = Math.min(encTime, minEncTime);
            minSigTime = Math.min(sigTime, minSigTime);
            totEncTime += encTime;
            totSigTime += sigTime;
        }
        System.out.println();
        System.out.println("Encrypt min " + minEncTime + "ms\tSign min " + minSigTime + "ms");
        System.out.println("Encrypt avg " + totEncTime/iterations + "ms\tSign avg " + totSigTime/iterations + "ms");
    }
    
    private long encBench() throws NoSuchAlgorithmException {
        long t1=System.currentTimeMillis();
        EncryptionParameters params = EncryptionParameters.APR2011_439;
        NtruEncrypt ntru = new NtruEncrypt(params);
        EncryptionKeyPair kp = ntru.generateKeyPair();
        for (int i=0; i<100; i++) {
            byte[] encrypted = ntru.encrypt(plain, kp.getPublic());
            byte[] decrypted = ntru.decrypt(encrypted, kp);
            if (!Arrays.equals(plain, Arrays.copyOf(decrypted, plain.length)))
                throw new NtruException("Decryption failure");
        }
        long t2 = System.currentTimeMillis();
        return t2 - t1;
    }
    
    private long signBench() {
        long t1=System.currentTimeMillis();
        SignatureParameters params = SignatureParameters.TEST157;
        NtruSign ntru = new NtruSign(params);
        SignatureKeyPair kp = ntru.generateKeyPair();
        for (int i=0; i<100; i++) {
            byte[] sig = ntru.sign(plain, kp);
            boolean pass = ntru.verify(plain, sig, kp.getPublic());
            if (!pass)
                throw new NtruException("Verification failure");
        }
        long t2 = System.currentTimeMillis();
        return t2 - t1;
    }
    
    public static void main(String[] args) throws Exception {
        new Benchmark().run();
    }
}