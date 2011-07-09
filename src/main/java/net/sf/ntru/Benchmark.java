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
        
        NtruEncrypt ntruEncrypt = new NtruEncrypt(EncryptionParameters.APR2011_439);
        NtruSign ntruSign = new NtruSign(SignatureParameters.APR2011_439_FAST);
        for (int i=0; i<iterations; i++) {
            long encKeyGenTime = encKeyGenBench(ntruEncrypt);
            System.out.print("EncKeyG " + encKeyGenTime + "ms");
            long encryptTime = encryptBench(ntruEncrypt);
            System.out.print("\tEncrypt " + encryptTime + "ms");
            long decryptTime = decryptBench(ntruEncrypt);
            System.out.print("\tDecrypt " + decryptTime + "ms");
            long sigKeyGenTime = sigKeyGenBench(ntruSign);
            System.out.print("\tSigKeyG " + sigKeyGenTime + "ms");
            long signTime = signBench(ntruSign);
            System.out.print("\tSign " + signTime + "ms");
            long verifyTime = verifyBench(ntruSign);
            System.out.print("\tVerify " + verifyTime + "ms");
            long totalTime = encKeyGenTime + encryptTime + decryptTime + sigKeyGenTime + signTime + verifyTime;
            System.out.println("\tTotal " + totalTime + "ms");
            
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
        System.out.println("    Min " + minEncKeyGenTime + "ms\t    Min " + minEncryptTime + "ms\t    Min " + minDecryptTime + "ms" +
                "\t    Min " + minSigKeyGenTime + "ms\t Min " + minSignTime + "ms\t   Min " + minVerifyTime + "ms\t   Min " + minTotalTime);
        System.out.println("    Avg " + totEncKeyGenTime/iterations + "ms\t    Avg " + totEncryptTime/iterations + "ms\t    Avg " + totDecryptTime/iterations + "ms" +
                "\t    Avg " + totSigKeyGenTime/iterations + "ms\t Avg " + totSignTime/iterations + "ms\t   Avg " + totVerifyTime/iterations + "ms\t   Avg " + totTotalTime/iterations);
    }
    
    private long encKeyGenBench(NtruEncrypt ntru) {
        long t1 = System.currentTimeMillis();
        for (int i=0; i<20; i++)
            encKeyPair = ntru.generateKeyPair();
        long t2 = System.currentTimeMillis();
        return t2 - t1;
    }
    
    private long encryptBench(NtruEncrypt ntru) {
        long t1 = System.currentTimeMillis();
        for (int i=0; i<100; i++)
            encrypted = ntru.encrypt(plain, encKeyPair.getPublic());
        long t2 = System.currentTimeMillis();
        return t2 - t1;
    }
    
    private long decryptBench(NtruEncrypt ntru) {
        long t1 = System.currentTimeMillis();
        for (int i=0; i<400; i++) {
            byte[] decrypted = ntru.decrypt(encrypted, encKeyPair);
            if (!Arrays.equals(plain, Arrays.copyOf(decrypted, plain.length)))
                throw new NtruException("Decryption failure");
        }
        long t2 = System.currentTimeMillis();
        return t2 - t1;
    }
    
    private long sigKeyGenBench(NtruSign ntru) {
        long t1 = System.currentTimeMillis();
        sigKeyPair = ntru.generateKeyPair();
        long t2 = System.currentTimeMillis();
        return t2 - t1;
    }
    
    private long signBench(NtruSign ntru) {
        long t1=System.currentTimeMillis();
        for (int i=0; i<100; i++) {
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
        for (int i=0; i<100; i++) {
            byte[] sig = ntru.sign(plain, sigKeyPair);
            boolean pass = ntru.verify(plain, sig, sigKeyPair.getPublic());
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