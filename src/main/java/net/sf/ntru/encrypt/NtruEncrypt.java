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

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import net.sf.ntru.encrypt.EncryptionParameters.TernaryPolynomialType;
import net.sf.ntru.exception.NtruException;
import net.sf.ntru.polynomial.DenseTernaryPolynomial;
import net.sf.ntru.polynomial.IntegerPolynomial;
import net.sf.ntru.polynomial.Polynomial;
import net.sf.ntru.polynomial.PolynomialGenerator;
import net.sf.ntru.polynomial.ProductFormPolynomial;
import net.sf.ntru.polynomial.SparseTernaryPolynomial;

/**
 * Encrypts, decrypts data and generates key pairs.<br/>
 * The parameter p is hardcoded to 3.
 */
public class NtruEncrypt {
    private EncryptionParameters params;
    
    /**
     * Constructs a new instance with a set of encryption parameters.
     * @param params encryption parameters
     */
    public NtruEncrypt(EncryptionParameters params) {
        this.params = params;
    }
    
    /**
     * Generates a new encryption key pair using two threads if possible.
     * @return a key pair
     */
    public EncryptionKeyPair generateKeyPair() {
        return generateKeyPair(new SecureRandom(), true);
    }
    
    /**
     * Generates a new encryption key pair in a single thread.
     * @return a key pair
     */
    public EncryptionKeyPair generateKeyPairSingleThread() {
        return generateKeyPair(new SecureRandom(), false);
    }
    
    /**
     * Generates an encryption key pair from a passphrase using two threads if possible.<br/>
     * Invoking this method with the same passphrase and salt will always return the
     * same key pair.
     * @param passphrase
     * @param salt salt for the passphrase; can be <code>null</code> but this is strongly discouraged
     * @return a key pair
     */
    public EncryptionKeyPair generateKeyPair(char[] passphrase, byte[] salt) {
        PassphraseBasedPRNG rng = new PassphraseBasedPRNG(passphrase, salt);
        return generateKeyPair(rng, rng.createBranch(), true);
    }
    
    /**
     * Generates an encryption key pair from a passphrase in a single thread.<br/>
     * Invoking this method with the same passphrase and salt will always return the
     * same key pair.
     * @param passphrase
     * @param salt salt for the passphrase; can be <code>null</code> but this is strongly discouraged
     * @return a key pair
     */
    public EncryptionKeyPair generateKeyPairSingleThread(char[] passphrase, byte[] salt) {
        Random rng = new PassphraseBasedPRNG(passphrase, salt);
        return generateKeyPair(rng, false);
    }
    
    /**
     * A convenience method that generates a random 128-bit salt vector for key pair generation.
     * @return a new salt vector
     */
    public byte[] generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
    }
    
    private EncryptionKeyPair generateKeyPair(Random rng, boolean multiThread) {
        return generateKeyPair(rng, rng, multiThread);
    }
    
    /**
     * Generates a new encryption key pair.
     * @param rngf the random number generator to use for generating the secret polynomial f
     * @param rngg the random number generator to use for generating the secret polynomial g
     * @param multiThread whether to use two threads; only has an effect if more than one virtual processor is available
     * @return a key pair
     */
    private EncryptionKeyPair generateKeyPair(Random rngf, final Random rngg, boolean multiThread) {
        int N = params.N;
        int q = params.q;
        int df = params.df;
        int df1 = params.df1;
        int df2 = params.df2;
        int df3 = params.df3;
        boolean fastFp = params.fastFp;
        boolean sparse = params.sparse;
        TernaryPolynomialType polyType = params.polyType;
        
        Polynomial t;
        IntegerPolynomial fq;
        IntegerPolynomial fp = null;
        
        // Choose a random g that is invertible mod q. Start a new thread if multiThread=true and more than one processor is available.
        Future<IntegerPolynomial> gResult = null;
        IntegerPolynomial g = null;
        if (multiThread && Runtime.getRuntime().availableProcessors()>1) {
            Callable<IntegerPolynomial> gTask = new Callable<IntegerPolynomial>() {
                @Override
                public IntegerPolynomial call() {
                    return generateG(rngg);
                }
            };
            ExecutorService executor = Executors.newSingleThreadExecutor();
            gResult = executor.submit(gTask);
            executor.shutdown();
        }
        else
            g = generateG(rngg);

        // choose a random f that is invertible mod 3 and q
        while (true) {
            IntegerPolynomial f;
            
            // choose random t, calculate f and fp
            if (fastFp) {
                // if fastFp=true, f is always invertible mod 3
                t = polyType==TernaryPolynomialType.SIMPLE ?
                        PolynomialGenerator.generateRandomTernary(N, df, df, sparse, rngf) :
                        ProductFormPolynomial.generateRandom(N, df1, df2, df3, df3, rngf);
                f = t.toIntegerPolynomial();
                f.mult(3);
                f.coeffs[0] += 1;
            }
            else {
                t = polyType==TernaryPolynomialType.SIMPLE ?
                        PolynomialGenerator.generateRandomTernary(N, df, df-1, sparse, rngf) :
                        ProductFormPolynomial.generateRandom(N, df1, df2, df3, df3-1, rngf);
                f = t.toIntegerPolynomial();
                fp = f.invertF3();
                if (fp == null)
                    continue;
            }
            
            fq = f.invertFq(q);
            if (fq != null)
                break;
        }
        
        // if fastFp=true, fp=1
        if (fastFp) {
            fp = new IntegerPolynomial(N);
            fp.coeffs[0] = 1;
        }
        
        // if g is being generated in a separate thread, wait for it to become available
        if (g == null)
            try {
                g = gResult.get();
            } catch (Exception e) {
                throw new NtruException(e);
            }
        
        IntegerPolynomial h = g.mult(fq, q);
        h.mult3(q);
        h.ensurePositive(q);
        g.clear();
        fq.clear();
        
        EncryptionPrivateKey priv = new EncryptionPrivateKey(t, fp, N, q, sparse, fastFp, polyType);
        EncryptionPublicKey pub = new EncryptionPublicKey(h, N, q);
        return new EncryptionKeyPair(priv, pub);
    }
    
    /**
     * Generates the ephemeral secret polynomial <code>g</code>.
     * @return
     */
    private IntegerPolynomial generateG(Random rng) {
        final int N = params.N;
        int dg = params.dg;
        
        while (true) {
            DenseTernaryPolynomial g = DenseTernaryPolynomial.generateRandom(N, dg, dg-1, rng);
            if (g.isInvertiblePow2())
                return g;
        }
    }
    
    /**
     * Encrypts a message.<br/>
     * See P1363.1 section 9.2.2.
     * @param m The message to encrypt
     * @param pubKey the public key to encrypt the message with
     * @return the encrypted message
     * @throws NtruException if the JRE doesn't implement the specified hash algorithm, the message is longer than <code>maxLenBytes</code>, or <code>maxLenBytes</code> is greater than 255
     */
    public byte[] encrypt(byte[] m, EncryptionPublicKey pubKey) {
        IntegerPolynomial pub = pubKey.h;
        int N = params.N;
        int q = params.q;
        int maxLenBytes = params.maxMsgLenBytes;
        int db = params.db;
        int bufferLenBits = params.bufferLenBits;
        int dm0 = params.dm0;
        int maxM1 = params.maxM1;
        int minCallsMask = params.minCallsMask;
        boolean hashSeed = params.hashSeed;
        
        int l = m.length;
        if (maxLenBytes > 255)
            throw new NtruException("llen values bigger than 1 are not supported");
        if (l > maxLenBytes)
            throw new NtruException("Message too long: " + l + ">" + maxLenBytes);
        
        SecureRandom rng = new SecureRandom();
        while (true) {
            // M = b|octL|m|p0
            byte[] b = new byte[db/8];
            rng.nextBytes(b);
            byte[] p0 = new byte[maxLenBytes+1-l];
            ByteBuffer mBuf = ByteBuffer.allocate((bufferLenBits+7)/8);
            mBuf.put(b);
            mBuf.put((byte)l);
            mBuf.put(m);
            mBuf.put(p0);
            byte[] M = mBuf.array();
            
            IntegerPolynomial mTrin = IntegerPolynomial.fromBinary3Sves(M, N, maxM1>0);   // don't use the constant coeff if maxM1 is set; see below
            
            byte[] sData = getSeed(m, pub, b);
            
            Polynomial r = generateBlindingPoly(sData);
            IntegerPolynomial R = r.mult(pub, q);
            byte[] oR4 = R.toBinary4();
            IntegerPolynomial mask = MGF(oR4, N, minCallsMask, hashSeed);
            mTrin.add(mask);
            
            // If df and dr are close to N/3, and the absolute value of mTrin.sumCoeffs() is
            // large enough, the message becomes vulnerable to a meet-in-the-middle attack.
            // To prevent this, we set the constant coefficient to zero but first check to ensure
            // sumCoeffs() is small enough to keep the likelihood of a decryption failure low.
            if (maxM1 > 0) {
                if (mTrin.sumCoeffs()>maxM1)
                    continue;
                mTrin.coeffs[0] = 0;
            }
            
            mTrin.mod3();
            
            if (mTrin.count(-1) < dm0)
                continue;
            if (mTrin.count(0) < dm0)
                continue;
            if (mTrin.count(1) < dm0)
                continue;
            
            R.add(mTrin, q);
            R.ensurePositive(q);
            return R.toBinary(q);
        }
    }

    /**
     * Generates a seed for the Blinding Polynomial Generation Function.
     * @param m the plain-text message
     * @param pub the public key
     * @param b <code>db</code> bits of random data
     * @return a byte array containing a seed value
     */
    private byte[] getSeed(byte[] m, IntegerPolynomial pub, byte[] b) {
        byte[] oid = params.oid;
        
        byte[] hTrunc = pub.toBinaryTrunc(params.q, params.pkLen/8);
        // sData = OID|m|b|hTrunc
        byte[] sData = new byte[oid.length + m.length + b.length + hTrunc.length];
        System.arraycopy(oid, 0, sData, 0, oid.length);
        int start = oid.length;
        System.arraycopy(m, 0, sData, start, m.length);
        start += m.length;
        System.arraycopy(b, 0, sData, start, b.length);
        start += b.length;
        System.arraycopy(hTrunc, 0, sData, start, hTrunc.length);
        return sData;
    }
    
    /**
     * Deterministically generates a blinding polynomial from a seed and a message representative.
     * @param seed
     * @return a blinding polynomial
     */
    private Polynomial generateBlindingPoly(byte[] seed) {
        int N = params.N;
        IndexGenerator ig = new IndexGenerator(seed, params);
        
        if (params.polyType == TernaryPolynomialType.PRODUCT) {
            SparseTernaryPolynomial r1 = SparseTernaryPolynomial.generateBlindingPoly(ig, N, params.dr1);
            SparseTernaryPolynomial r2 = SparseTernaryPolynomial.generateBlindingPoly(ig, N, params.dr2);
            SparseTernaryPolynomial r3 = SparseTernaryPolynomial.generateBlindingPoly(ig, N, params.dr3);
            return new ProductFormPolynomial(r1, r2, r3);
        }
        else
            if (params.sparse)
                return SparseTernaryPolynomial.generateBlindingPoly(ig, N, params.dr);
            else
                return DenseTernaryPolynomial.generateBlindingPoly(ig, N, params.dr);
    }
    
    /**
     * An implementation of MGF-TP-1 from P1363.1 section 8.4.1.1.
     * @param seed
     * @param N
     * @param minCallsMask
     * @param hashSeed whether to hash the seed
     * @return
     * @throws NtruException if the JRE doesn't implement the specified hash algorithm
     */
    private IntegerPolynomial MGF(byte[] seed, int N, int minCallsMask, boolean hashSeed) {
        MessageDigest hashAlg;
        try {
            hashAlg = MessageDigest.getInstance(params.hashAlg);
        } catch (NoSuchAlgorithmException e) {
            throw new NtruException(e);
        }
        
        int hashLen = hashAlg.getDigestLength();
        ByteBuffer buf = ByteBuffer.allocate(minCallsMask*hashLen);
        byte[] Z = hashSeed ? hashAlg.digest(seed) : seed;
        int counter = 0;
        while (counter < minCallsMask) {
            ByteBuffer hashInput = ByteBuffer.allocate(Z.length + 4);
            hashInput.put(Z);
            hashInput.putInt(counter);
            byte[] hash = hashAlg.digest(hashInput.array());
            buf.put(hash);
            counter++;
        }
        
        IntegerPolynomial i = new IntegerPolynomial(N);
        while (true) {
            int cur = 0;
            for (byte o: buf.array()) {
                int O = (int)o & 0xFF;
                if (O >= 243)   // 243 = 3^5
                    continue;
                
                for (int terIdx=0; terIdx<4; terIdx++) {
                    int rem3 = O % 3;
                    i.coeffs[cur] = rem3 - 1;
                    cur++;
                    if (cur == N)
                        return i;
                    O = (O-rem3) / 3;
                }
                
                i.coeffs[cur] = O - 1;
                cur++;
                if (cur == N)
                    return i;
            }
            
            if (cur >= N)
                return i;
            
            buf = ByteBuffer.allocate(hashLen);
            ByteBuffer hashInput = ByteBuffer.allocate(Z.length + 4);
            hashInput.put(Z);
            hashInput.putInt(counter);
            byte[] hash = hashAlg.digest(hashInput.array());
            buf.put(hash);
            counter++;
        }
    }

    /**
     * Decrypts a message.<br/>
     * See P1363.1 section 9.2.3.
     * @param data The message to decrypt
     * @param kp a key pair that contains the public key the message was encrypted with, and the corresponding private key
     * @return the decrypted message
     * @throws NtruException if the JRE doesn't implement the specified hash algorithm, the encrypted data is invalid, or <code>maxLenBytes</code> is greater than 255
     */
    public byte[] decrypt(byte[] data, EncryptionKeyPair kp) {
        Polynomial priv_t = kp.priv.t;
        IntegerPolynomial priv_fp = kp.priv.fp;
        IntegerPolynomial pub = kp.pub.h;
        int N = params.N;
        int q = params.q;
        int db = params.db;
        int maxMsgLenBytes = params.maxMsgLenBytes;
        int dm0 = params.dm0;
        int maxM1 = params.maxM1;
        int minCallsMask = params.minCallsMask;
        boolean hashSeed = params.hashSeed;
        
        if (maxMsgLenBytes > 255)
            throw new NtruException("maxMsgLenBytes values bigger than 255 are not supported");
        
        int bLen = db / 8;
        
        IntegerPolynomial e = IntegerPolynomial.fromBinary(data, N, q);
        IntegerPolynomial ci = decrypt(e, priv_t, priv_fp);
        
        if (ci.count(-1) < dm0)
            throw new NtruException("Less than dm0 coefficients equal -1");
        if (ci.count(0) < dm0)
            throw new NtruException("Less than dm0 coefficients equal 0");
        if (ci.count(1) < dm0)
            throw new NtruException("Less than dm0 coefficients equal 1");
        
        IntegerPolynomial cR = e;
        cR.sub(ci);
        cR.modPositive(q);
        byte[] coR4 = cR.toBinary4();
        IntegerPolynomial mask = MGF(coR4, N, minCallsMask, hashSeed);
        IntegerPolynomial cMTrin = ci;
        cMTrin.sub(mask);
        cMTrin.mod3();
        byte[] cM = cMTrin.toBinary3Sves(maxM1>0);
        
        ByteBuffer buf = ByteBuffer.wrap(cM);
        byte[] cb = new byte[bLen];
        buf.get(cb);
        int cl = buf.get() & 0xFF;   // llen=1, so read one byte
        if (cl > maxMsgLenBytes)
            throw new NtruException("Message too long: " + cl + ">" + maxMsgLenBytes);
        byte[] cm = new byte[cl];
        buf.get(cm);
        byte[] p0 = new byte[buf.remaining()];
        buf.get(p0);
        if (!Arrays.equals(p0, new byte[p0.length]))
            throw new NtruException("The message is not followed by zeroes");
        
        byte[] sData = getSeed(cm, pub, cb);
        
        Polynomial cr = generateBlindingPoly(sData);
        IntegerPolynomial cRPrime = cr.mult(pub);
        cRPrime.modPositive(q);
        if (!cRPrime.equals(cR))
            throw new NtruException("Invalid message encoding");
       
        return cm;
    }
    
    /**
     * 
     * @param e
     * @param priv_t a polynomial such that if <code>fastFp=true</code>, <code>f=1+3*priv_t</code>; otherwise, <code>f=priv_t</code>
     * @param priv_fp
     * @return
     */
    IntegerPolynomial decrypt(IntegerPolynomial e, Polynomial priv_t, IntegerPolynomial priv_fp) {
        int q = params.q;
        
        IntegerPolynomial a;
        if (params.fastFp) {
            a = priv_t.mult(e, q);
            a.mult(3);
            a.add(e);
        }
        else
            a = priv_t.mult(e, q);
        a.center0(q);
        a.mod3();
        
        IntegerPolynomial c = params.fastFp ? a : new DenseTernaryPolynomial(a).mult(priv_fp, 3);
        c.center0(3);
        return c;
    }
}