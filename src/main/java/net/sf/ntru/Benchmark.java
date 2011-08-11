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

import java.util.Arrays;

public class Benchmark {
    private static final int NUM_ENC_KEY_GEN = 20;
    private static final int NUM_ENCRYPT = 100;
    private static final int NUM_DECRYPT = 400;
    private static final int NUM_SIG_KEY_GEN = 1;
    private static final int NUM_SIGN = 100;
    private static final int NUM_VERIFY = 100;
    
    private byte[] plain = "test message".getBytes();
    private byte[] encrypted;
    private EncryptionKeyPair encKeyPair;
    private SignatureKeyPair sigKeyPair;
    
    private void run() {
        long minEncKeyGenTime = Long.MAX_VALUE;
        long minEncryptTime = Long.MAX_VALUE;
        long minDecryptTime = Long.MAX_VALUE;
        long minSigKeyGenTime = Long.MAX_VALUE;
        long minSignTime = Long.MAX_VALUE;
        long minVerifyTime = Long.MAX_VALUE;
        long minTotalTime = Long.MAX_VALUE;
        long totEncKeyGenTime = 0;
        long totEncryptTime = 0;
        long totDecryptTime = 0;
        long totSigKeyGenTime = 0;
        long totSignTime = 0;
        long totVerifyTime = 0;
        long totTotalTime = 0;
        int iterations = 5;
        
        NtruEncrypt ntruEncrypt = new NtruEncrypt(EncryptionParameters.APR2011_439_FAST);
        NtruSign ntruSign = new NtruSign(SignatureParameters.APR2011_439_FAST);
        System.out.println("   EncKeyGen    Encrypt    Decrypt  SigKeyGen       Sign     Verify      Total");
        System.out.println();
        for (int i=0; i<iterations; i++) {
            long encKeyGenTime = encKeyGenBench(ntruEncrypt);
            System.out.print("   " + formatDuration(encKeyGenTime) + "  ");
            long encryptTime = encryptBench(ntruEncrypt);
            System.out.print(formatDuration(encryptTime) + "  ");
            long decryptTime = decryptBench(ntruEncrypt);
            System.out.print(formatDuration(decryptTime) + "  ");
            long sigKeyGenTime = sigKeyGenBench(ntruSign);
            System.out.print(formatDuration(sigKeyGenTime) + "  ");
            long signTime = signBench(ntruSign);
            System.out.print(formatDuration(signTime) + "  ");
            long verifyTime = verifyBench(ntruSign);
            System.out.print(formatDuration(verifyTime) + "  ");
            long totalTime = encKeyGenTime + encryptTime + decryptTime + sigKeyGenTime + signTime + verifyTime;
            System.out.println(formatDuration(totalTime));
            
            minEncKeyGenTime = Math.min(encKeyGenTime, minEncKeyGenTime);
            minEncryptTime = Math.min(encryptTime, minEncryptTime);
            minDecryptTime = Math.min(decryptTime, minDecryptTime);
            minEncKeyGenTime = Math.min(encKeyGenTime, minEncKeyGenTime);
            minSigKeyGenTime = Math.min(sigKeyGenTime, minSigKeyGenTime);
            minSignTime = Math.min(signTime, minSignTime);
            minVerifyTime = Math.min(verifyTime, minVerifyTime);
            minTotalTime = Math.min(totalTime, minTotalTime);
            totEncKeyGenTime += encKeyGenTime;
            totEncryptTime += encryptTime;
            totDecryptTime += decryptTime;
            totSigKeyGenTime += sigKeyGenTime;
            totSignTime += signTime;
            totVerifyTime += verifyTime;
            totTotalTime += totalTime;
        }
        System.out.println();
        System.out.println("Min" + formatDuration(minEncKeyGenTime) + "  " + formatDuration(minEncryptTime) + "  " + formatDuration(minDecryptTime) + "  " + 
                formatDuration(minSigKeyGenTime) + "  " + formatDuration(minSignTime) + "  " + formatDuration(minVerifyTime) + "  " + formatDuration(minTotalTime));
        System.out.println("Avg" + formatDuration(totEncKeyGenTime/iterations) + "  " + formatDuration(totEncryptTime/iterations) + "  " + formatDuration(totDecryptTime/iterations) + "  " +
                formatDuration(totSigKeyGenTime/iterations) + "  " + formatDuration(totSignTime/iterations) + "  " + formatDuration(totVerifyTime/iterations) + "  " + formatDuration(totTotalTime/iterations));
        System.out.println("Ops" + formatOpsPerSecond(minEncKeyGenTime, NUM_ENC_KEY_GEN) + "  " + formatOpsPerSecond(minEncryptTime, NUM_ENCRYPT) + "  " + formatOpsPerSecond(minDecryptTime, NUM_DECRYPT) + "  " +
                formatOpsPerSecond(minSigKeyGenTime, NUM_SIG_KEY_GEN) + "  " + formatOpsPerSecond(minSignTime, NUM_SIGN) + "  " + formatOpsPerSecond(minVerifyTime, NUM_VERIFY));
    }
    
    /**
     * 
     * @param duration time it took for all <code>numOps</code> operations to complete
     * @param numOps number of operations performed
     * @return
     */
    private String formatOpsPerSecond(long duration, int numOps) {
        double ops = 1000.0 / duration * numOps;
        return String.format("%7.2f/s", ops);
    }
    
    private String formatDuration(long n) {
        return String.format("%1$7sms", n);
    }
    
    private long encKeyGenBench(NtruEncrypt ntru) {
        long t1 = System.currentTimeMillis();
        for (int i=0; i<NUM_ENC_KEY_GEN; i++)
            encKeyPair = ntru.generateKeyPair();
        long t2 = System.currentTimeMillis();
        return t2 - t1;
    }
    
    private long encryptBench(NtruEncrypt ntru) {
        long t1 = System.currentTimeMillis();
        for (int i=0; i<NUM_ENCRYPT; i++)
            encrypted = ntru.encrypt(plain, encKeyPair.getPublic());
        long t2 = System.currentTimeMillis();
        return t2 - t1;
    }
    
    private long decryptBench(NtruEncrypt ntru) {
        long t1 = System.currentTimeMillis();
        for (int i=0; i<NUM_DECRYPT; i++) {
            byte[] decrypted = ntru.decrypt(encrypted, encKeyPair);
            if (!Arrays.equals(plain, Arrays.copyOf(decrypted, plain.length)))
                throw new NtruException("Decryption failure");
        }
        long t2 = System.currentTimeMillis();
        return t2 - t1;
    }
    
    private long sigKeyGenBench(NtruSign ntru) {
        long t1 = System.currentTimeMillis();
        for (int i=0; i<NUM_SIG_KEY_GEN; i++)
            sigKeyPair = ntru.generateKeyPair();
        long t2 = System.currentTimeMillis();
        return t2 - t1;
    }
    
    private long signBench(NtruSign ntru) {
        long t1=System.currentTimeMillis();
        for (int i=0; i<NUM_SIGN; i++) {
            byte[] sig = ntru.sign(plain, sigKeyPair);
            boolean pass = ntru.verify(plain, sig, sigKeyPair.getPublic());
            if (!pass)
                throw new NtruException("Verification failure");
        }
        long t2 = System.currentTimeMillis();
        return t2 - t1;
    }
    
    private long verifyBench(NtruSign ntru) {
        long t1=System.currentTimeMillis();
        for (int i=0; i<NUM_VERIFY; i++) {
            byte[] sig = ntru.sign(plain, sigKeyPair);
            boolean pass = ntru.verify(plain, sig, sigKeyPair.getPublic());
            if (!pass)
                throw new NtruException("Verification failure");
        }
        long t2 = System.currentTimeMillis();
        return t2 - t1;
    }
    
    public static void main(String[] args) {
        new Benchmark().run();
    }
}