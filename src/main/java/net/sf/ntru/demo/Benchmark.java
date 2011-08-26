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

package net.sf.ntru.demo;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.text.DecimalFormat;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;

import net.sf.ntru.encrypt.EncryptionKeyPair;
import net.sf.ntru.encrypt.EncryptionParameters;
import net.sf.ntru.encrypt.EncryptionPublicKey;
import net.sf.ntru.encrypt.NtruEncrypt;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Benchmarks NTRUEncrypt against ECC and RSA.
 */
public class Benchmark {
    private static final int PLAIN_TEXT_SIZE = 32;
    
    private static void printUsage() {
        System.out.println("Usage: Benchmark [alg]");
        System.out.println();
        System.out.println("alg can be one of:");
        System.out.println("  rsa3072gen");
        System.out.println("  rsa3072enc");
        System.out.println("  rsa3072dec");
        System.out.println("  rsa15360gen");
        System.out.println("  rsa15360enc");
        System.out.println("  rsa15360dec");
        System.out.println("  ecc256gen");
        System.out.println("  ecc256enc");
        System.out.println("  ecc256dec");
        System.out.println("  ecc521gen");
        System.out.println("  ecc521enc");
        System.out.println("  ecc521dec");
        System.out.println("  ntru439gen");
        System.out.println("  ntru439enc");
        System.out.println("  ntru439dec");
        System.out.println("  ntru743gen");
        System.out.println("  ntru743enc");
        System.out.println("  ntru743dec");
        System.out.println("If alg is not specified, all algorithms except rsa15360* are benchmarked.");
    }
    
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        
        if (args.length < 1) {
            rsa3072gen();
            rsa3072enc();
            rsa3072dec();
            ecc256gen();
            ecc256enc();
            ecc256dec();
            ecc521gen();
            ecc521enc();
            ecc521dec();
            ntru439gen();
            ntru439enc();
            ntru439dec();
            ntru743gen();
            ntru743enc();
            ntru743dec();
        }
        else if ("rsa3072gen".equals(args[0]))  rsa3072gen();
        else if ("rsa3072enc".equals(args[0]))  rsa3072enc();
        else if ("rsa3072dec".equals(args[0]))  rsa3072dec();
        else if ("rsa15360gen".equals(args[0])) rsa15360gen();
        else if ("rsa15360enc".equals(args[0])) rsa15360enc();
        else if ("rsa15360dec".equals(args[0])) rsa15360dec();
        else if ("ecc256gen".equals(args[0]))   ecc256gen();
        else if ("ecc256enc".equals(args[0]))   ecc256enc();
        else if ("ecc256dec".equals(args[0]))   ecc256dec();
        else if ("ecc521gen".equals(args[0]))   ecc521gen();
        else if ("ecc521enc".equals(args[0]))   ecc521enc();
        else if ("ecc521dec".equals(args[0]))   ecc521dec();
        else if ("ntru439gen".equals(args[0]))  ntru439gen();
        else if ("ntru439enc".equals(args[0]))  ntru439enc();
        else if ("ntru439dec".equals(args[0]))  ntru439dec();
        else if ("ntru743gen".equals(args[0]))  ntru743gen();
        else if ("ntru743enc".equals(args[0]))  ntru743enc();
        else if ("ntru743dec".equals(args[0]))  ntru743dec();
        else
            printUsage();
    }
    
    private static void rsa3072gen() throws Exception {
        new RsaBenchmark(3072, 1, 2).keyGenBench();
    }
    
    private static void rsa3072enc() throws Exception {
        new RsaBenchmark(3072, 1000, 2000).encryptBench();
    }
    
    private static void rsa3072dec() throws Exception {
        new RsaBenchmark(3072, 20, 40).decryptBench();
    }
    
    private static void rsa15360gen() throws Exception {
        new RsaBenchmark(15360, 1, 2).keyGenBench();
    }
    
    private static void rsa15360enc() throws Exception {
        new RsaBenchmark(15360, 100, 200).encryptBench();
    }
    
    private static void rsa15360dec() throws Exception {
        new RsaBenchmark(15360, 3, 6).decryptBench();
    }
    
    private static void ecc256gen() throws Exception {
        new EcdhBenchmark("P-256", 256, 100, 200).keyGenBench();
    }
    
    private static void ecc256enc() throws Exception {
        new EcdhBenchmark("P-256", 256, 50, 100).encryptBench();
    }
    
    private static void ecc256dec() throws Exception {
        new EcdhBenchmark("P-256", 256, 100, 200).decryptBench();
    }
    
    private static void ecc521gen() throws Exception {
        new EcdhBenchmark("P-521", 521, 20, 40).keyGenBench();
    }
    
    private static void ecc521enc() throws Exception {
        new EcdhBenchmark("P-521", 521, 10, 20).encryptBench();
    }
    
    private static void ecc521dec() throws Exception {
        new EcdhBenchmark("P-521", 521, 20, 40).decryptBench();
    }
    
    private static void ntru439gen() throws Exception {
        new NtruEncryptBenchmark(EncryptionParameters.APR2011_439_FAST, 100, 200).keyGenBench();
    }
    
    private static void ntru439enc() throws Exception {
        new NtruEncryptBenchmark(EncryptionParameters.APR2011_439_FAST, 2000, 4000).encryptBench();
    }
    
    private static void ntru439dec() throws Exception {
        new NtruEncryptBenchmark(EncryptionParameters.APR2011_439_FAST, 4000, 8000).decryptBench();
    }
    
    private static void ntru743gen() throws Exception {
        new NtruEncryptBenchmark(EncryptionParameters.APR2011_743_FAST, 40, 80).keyGenBench();
    }
    
    private static void ntru743enc() throws Exception {
        new NtruEncryptBenchmark(EncryptionParameters.APR2011_743_FAST, 750, 1500).encryptBench();
    }
    
    private static void ntru743dec() throws Exception {
        new NtruEncryptBenchmark(EncryptionParameters.APR2011_743_FAST, 2000, 4000).decryptBench();
    }
    
    private static void printResults(String alg, long duration, int iterations) {
        DecimalFormat format = new DecimalFormat("0.00");
        System.out.println("-------------------------------------------------------------------------------");
        System.out.println("Result for " + alg + ": " + format.format(duration/1000000.0) + "ms total, " +
                format.format(duration/1000000.0/iterations) + "ms/op, " +
                format.format(iterations*1000000000.0/duration) + " ops/sec");
        System.out.println("-------------------------------------------------------------------------------");
    }
    
    private static byte[] generatePlainText() {
        SecureRandom rng = new SecureRandom();
        byte[] plainText = new byte[PLAIN_TEXT_SIZE];
        rng.nextBytes(plainText);
        return plainText;
    }
    
    private static class RsaBenchmark {
        private int keySize;
        private int warmupIterations;
        private int benchIterations;
        private byte[] plainText;
        private Cipher ciph;
        private KeyPairGenerator keyGen;
        
        private RsaBenchmark(int keySize, int warmupIterations, int benchIterations) throws Exception {
            this.keySize = keySize;
            this.warmupIterations = warmupIterations;
            this.benchIterations = benchIterations;
            
            plainText = generatePlainText();
            ciph = Cipher.getInstance("RSA/NONE/PKCS1Padding", "BC");
            keyGen = KeyPairGenerator.getInstance("RSA", "BC");
            keyGen.initialize(keySize);
        }
        
        private void keyGenBench() throws Exception {
            System.out.println("Warming up RSA...");
            rsaKeyGenIterations(warmupIterations, keyGen);
            System.out.println("Finished warming up RSA");
            System.out.println("Benchmarking RSA key generation...");
            long t1 = System.nanoTime();
            rsaKeyGenIterations(benchIterations, keyGen);
            long t2 = System.nanoTime();
            printResults("RSA-" + keySize + " key generation", t2-t1, benchIterations);
        }
        
        private void encryptBench() throws Exception {
            KeyPair kp = keyGen.generateKeyPair();
            
            System.out.println("Warming up RSA...");
            rsaEncryptIterations(warmupIterations, keyGen, kp.getPublic());
            System.out.println("Finished warming up RSA");
            System.out.println("Benchmarking RSA encryption...");
            long t1 = System.nanoTime();
            rsaEncryptIterations(benchIterations, keyGen, kp.getPublic());
            long t2 = System.nanoTime();
            printResults("RSA-" + keySize + " encryption", t2-t1, benchIterations);
        }
        
        private void decryptBench() throws Exception {
            KeyPair kp = keyGen.generateKeyPair();
            
            ciph.init(Cipher.ENCRYPT_MODE, kp.getPublic());
            byte[] encryptedText = ciph.doFinal(plainText);
            
            System.out.println("Warming up RSA...");
            ecdhDecryptIterations(warmupIterations, encryptedText, kp.getPrivate());
            System.out.println("Finished warming up RSA");
            System.out.println("Benchmarking RSA decryption...");
            long t1 = System.nanoTime();
            ecdhDecryptIterations(benchIterations, encryptedText, kp.getPrivate());
            long t2 = System.nanoTime();
            printResults("RSA-" + keySize + " decryption", t2-t1, benchIterations);
        }
        
        private void rsaKeyGenIterations(int iterations, KeyPairGenerator keyGen) throws Exception {
            for (int i=0; i<iterations; i++)
                keyGen.generateKeyPair();
        }
        
        private void rsaEncryptIterations(int iterations, KeyPairGenerator keyGen, PublicKey pk) throws Exception {
            for (int i=0; i<iterations; i++) {
                ciph.init(Cipher.ENCRYPT_MODE, pk);
                ciph.doFinal(plainText);
            }
        }
        
        private void ecdhDecryptIterations(int iterations, byte[] encryptedText, PrivateKey pk) throws Exception {
            for (int i=0; i<iterations; i++) {
                ciph.init(Cipher.DECRYPT_MODE, pk);
                ciph.doFinal(encryptedText);
            }
        }
    }

    private static class EcdhBenchmark {
        private int keySize;
        private int warmupIterations;
        private int benchIterations;
        private KeyPairGenerator keyGen;
        
        private EcdhBenchmark(String curveName, int keySize, int warmupIterations, int benchIterations) throws Exception {
            this.keySize = keySize;
            this.warmupIterations = warmupIterations;
            this.benchIterations = benchIterations;
            keyGen = KeyPairGenerator.getInstance("ECDH", "BC");
            ECGenParameterSpec params = new ECGenParameterSpec(curveName);
            keyGen.initialize(params);
        }
        
        private void keyGenBench() throws Exception {
            System.out.println("Warming up ECDH...");
            ecdhKeyGenIterations(warmupIterations, keyGen);
            System.out.println("Finished warming up ECDH");
            System.out.println("Benchmarking ECDH key generation...");
            long t1 = System.nanoTime();
            ecdhKeyGenIterations(benchIterations, keyGen);
            long t2 = System.nanoTime();
            printResults("ECDH-" + keySize + " key generation", t2-t1, benchIterations);
        }
        
        private void encryptBench() throws Exception {
            KeyPair kp = keyGen.generateKeyPair();
            
            System.out.println("Warming up ECDH...");
            ecdhEncryptIterations(warmupIterations, keyGen, kp.getPublic());
            System.out.println("Finished warming up ECDH");
            System.out.println("Benchmarking ECDH encryption...");
            long t1 = System.nanoTime();
            ecdhEncryptIterations(benchIterations, keyGen, kp.getPublic());
            long t2 = System.nanoTime();
            printResults("ECDH-" + keySize + " encryption", t2-t1, benchIterations);
        }
        
        private void decryptBench() throws Exception {
            KeyPair kp = keyGen.generateKeyPair();
            KeyPair ephemKp = keyGen.generateKeyPair();
            
            System.out.println("Warming up ECDH...");
            ecdhDecryptIterations(warmupIterations, keyGen, kp.getPrivate(), ephemKp.getPublic());
            System.out.println("Finished warming up ECDH");
            System.out.println("Benchmarking ECDH decryption...");
            long t1 = System.nanoTime();
            ecdhDecryptIterations(benchIterations, keyGen, kp.getPrivate(), ephemKp.getPublic());
            long t2 = System.nanoTime();
            printResults("ECDH-" + keySize + " decryption", t2-t1, benchIterations);
        }
        
        private void ecdhKeyGenIterations(int iterations, KeyPairGenerator keyGen) throws Exception {
            for (int i=0; i<iterations; i++)
                keyGen.generateKeyPair();
        }
        
        private void ecdhEncryptIterations(int iterations, KeyPairGenerator keyGen, PublicKey pk) throws Exception {
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            for (int i=0; i<iterations; i++) {
                KeyPair ephemKp = keyGen.generateKeyPair();
                ka.init(ephemKp.getPrivate());
                ka.doPhase(pk, true);
                ka.generateSecret();
            }
        }
        
        private void ecdhDecryptIterations(int iterations, KeyPairGenerator keyGen, PrivateKey pk, PublicKey ephemPk) throws Exception {
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            for (int i=0; i<iterations; i++) {
                ka.init(pk);
                ka.doPhase(ephemPk, true);
                ka.generateSecret();
            }
        }
    }

    private static class NtruEncryptBenchmark {
        private EncryptionParameters params;
        private int warmupIterations;
        private int benchIterations;
        private NtruEncrypt ntru;
        
        private NtruEncryptBenchmark(EncryptionParameters params, int warmupIterations, int benchIterations) {
            this.params = params;
            this.warmupIterations = warmupIterations;
            this.benchIterations = benchIterations;
            ntru = new NtruEncrypt(params);
        }
        
        private void keyGenBench() {
            System.out.println("Warming up NTRU...");
            ntruKeyGenIterations(warmupIterations, ntru);
            System.out.println("Finished warming up NTRU");
            System.out.println("Benchmarking NTRU key generation...");
            long t1 = System.nanoTime();
            ntruKeyGenIterations(benchIterations, ntru);
            long t2 = System.nanoTime();
            printResults("NTRU-" + params.N + " key generation", t2-t1, benchIterations);
        }
        
        private void encryptBench() {
            byte[] plainText = generatePlainText();
            EncryptionKeyPair kp = ntru.generateKeyPair();
            System.out.println("Warming up NTRU...");
            ntruEncryptIterations(warmupIterations, plainText, ntru, kp.getPublic());
            System.out.println("Finished warming up NTRU");
            System.out.println("Benchmarking NTRU encryption...");
            long t1 = System.nanoTime();
            ntruEncryptIterations(benchIterations, plainText, ntru, kp.getPublic());
            long t2 = System.nanoTime();
            printResults("NTRU-" + params.N + " encryption", t2-t1, benchIterations);
        }
        
        private void decryptBench() {
            byte[] plainText = generatePlainText();
            EncryptionKeyPair kp = ntru.generateKeyPair();
            byte[] encryptedText = ntru.encrypt(plainText, kp.getPublic());
            System.out.println("Warming up NTRU...");
            ntruDecryptIterations(warmupIterations, encryptedText, ntru, kp);
            System.out.println("Finished warming up NTRU");
            System.out.println("Benchmarking NTRU decryption...");
            long t1 = System.nanoTime();
            ntruDecryptIterations(benchIterations, encryptedText, ntru, kp);
            long t2 = System.nanoTime();
            printResults("NTRU-" + params.N + " decryption", t2-t1, benchIterations);
        }
        
        private void ntruKeyGenIterations(int iterations, NtruEncrypt ntru) {
            for (int i=0; i<iterations; i++)
                ntru.generateKeyPair();
        }
        
        private void ntruEncryptIterations(int iterations, byte[] plainText, NtruEncrypt ntru, EncryptionPublicKey key) {
            for (int i=0; i<iterations; i++)
                ntru.encrypt(plainText, key);
        }
        
        private void ntruDecryptIterations(int iterations, byte[] encryptedText, NtruEncrypt ntru, EncryptionKeyPair kp) {
            for (int i=0; i<iterations; i++)
                ntru.decrypt(encryptedText, kp);
        }
    }
}