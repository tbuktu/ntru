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

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
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
        return generateKeyPair(true);
    }
    
    /**
     * Generates a new encryption key pair in a single thread.
     * @return a key pair
     */
    public EncryptionKeyPair generateKeyPairSingleThread() {
        return generateKeyPair(false);
    }
    
    /**
     * Generates a new encryption key pair.
     * @param multiThread whether to use two threads; only has an effect if more than one virtual processor is available
     * @return a key pair
     */
    private EncryptionKeyPair generateKeyPair(boolean multiThread) {
        int N = params.N;
        int q = params.q;
        int df = params.df;
        int df1 = params.df1;
        int df2 = params.df2;
        int df3 = params.df3;
        boolean fastFp = params.fastFp;
        boolean sparse = params.sparse;
        
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
                    return generateG();
                }
            };
            ExecutorService executor = Executors.newSingleThreadExecutor();
            gResult = executor.submit(gTask);
            executor.shutdown();
        }
        else
            g = generateG();

        // choose a random f that is invertible mod 3 and q
        while (true) {
            IntegerPolynomial f;
            
            // choose random t, calculate f and fp
            if (fastFp) {
                // if fastFp=true, f is always invertible mod 3
                t = params.polyType==TernaryPolynomialType.SIMPLE ? PolynomialGenerator.generateRandomTernary(N, df, df, sparse) : ProductFormPolynomial.generateRandom(N, df1, df2, df3, df3);
                f = t.toIntegerPolynomial();
                f.mult(3);
                f.coeffs[0] += 1;
            }
            else {
                t = params.polyType==TernaryPolynomialType.SIMPLE ? PolynomialGenerator.generateRandomTernary(N, df, df-1, sparse) : ProductFormPolynomial.generateRandom(N, df1, df2, df3, df3-1);
                f = t.toIntegerPolynomial();
                fp = f.invertF3();
                if (fp == null)
                    continue;
            }
            
            fq = f.invertFq(q);
            if (fq == null)
                continue;
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
        
        EncryptionPrivateKey priv = new EncryptionPrivateKey(t, fp, params);
        EncryptionPublicKey pub = new EncryptionPublicKey(h, params);
        return new EncryptionKeyPair(priv, pub);
    }
    
    /**
     * Generates the ephemeral secret polynomial <code>g</code>.
     * @return
     */
    private IntegerPolynomial generateG() {
        final int N = params.N;
        final int q = params.q;
        int dg = params.dg;
        
        while (true) {
            DenseTernaryPolynomial g = DenseTernaryPolynomial.generateRandom(N, dg, dg-1);
            if (g.invertFq(q) != null)
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
        int pkLen = params.pkLen;
        int minCallsMask = params.minCallsMask;
        boolean hashSeed = params.hashSeed;
        byte[] oid = params.oid;
        
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
            ByteBuffer mBuf = ByteBuffer.allocate(bufferLenBits/8);
            mBuf.put(b);
            mBuf.put((byte)l);
            mBuf.put(m);
            mBuf.put(p0);
            byte[] M = mBuf.array();
            
            IntegerPolynomial mTrin = IntegerPolynomial.fromBinary3Sves(M, N);
            
            // sData = OID|m|b|hTrunc
            byte[] bh = pub.toBinary(q);
            byte[] hTrunc = Arrays.copyOf(bh, pkLen/8);
            ByteBuffer sDataBuffer = ByteBuffer.allocate(oid.length + l + b.length + hTrunc.length);
            sDataBuffer.put(oid);
            sDataBuffer.put(m);
            sDataBuffer.put(b);
            sDataBuffer.put(hTrunc);
            byte[] sData = sDataBuffer.array();
            
            Polynomial r = generateBlindingPoly(sData, M);
            IntegerPolynomial R = r.mult(pub, q);
            IntegerPolynomial R4 = R.clone();
            R4.modPositive(4);
            byte[] oR4 = R4.toBinary(4);
            IntegerPolynomial mask = MGF(oR4, N, minCallsMask, hashSeed);
            mTrin.add(mask);
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
     * Deterministically generates a blinding polynomial from a seed and a message representative.
     * @param seed
     * @param M message representative
     * @return a blinding polynomial
     */
    private Polynomial generateBlindingPoly(byte[] seed, byte[] M) {
        IndexGenerator ig = new IndexGenerator(seed, params);
        
        if (params.polyType == TernaryPolynomialType.PRODUCT) {
            SparseTernaryPolynomial r1 = new SparseTernaryPolynomial(generateBlindingCoeffs(ig, params.dr1));
            SparseTernaryPolynomial r2 = new SparseTernaryPolynomial(generateBlindingCoeffs(ig, params.dr2));
            SparseTernaryPolynomial r3 = new SparseTernaryPolynomial(generateBlindingCoeffs(ig, params.dr3));
            return new ProductFormPolynomial(r1, r2, r3);
        }
        else {
            int dr = params.dr;
            boolean sparse = params.sparse;
            int[] r = generateBlindingCoeffs(ig, dr);
            if (sparse)
                return new SparseTernaryPolynomial(r);
            else
                return new DenseTernaryPolynomial(r);
        }
    }
    
    /**
     * Generates an <code>int</code> array containing <code>dr</code> elements equal to <code>1</code>
     * and <code>dr</code> elements equal to <code>-1</code> using an index generator.
     * @param ig an index generator
     * @param dr number of ones / negative ones
     * @return an array containing numbers between <code>-1</code> and <code>1</code>
     */
    private int[] generateBlindingCoeffs(IndexGenerator ig, int dr) {
        int N = params.N;
        
        int[] r = new int[N];
        for (int coeff=-1; coeff<=1; coeff+=2) {
            int t = 0;
            while (t < dr) {
                int i = ig.nextIndex();
                if (r[i] == 0) {
                    r[i] = coeff;
                    t++;
                }
            }
        }
        
        return r;
    }
    
    /**
     * An implementation of MGF-TP-1 from P1363.1 section 8.4.1.1.
     * @param seed
     * @param N
     * @param minCallsR
     * @param hashSeed whether to hash the seed
     * @return
     * @throws NtruException if the JRE doesn't implement the specified hash algorithm
     */
    private IntegerPolynomial MGF(byte[] seed, int N, int minCallsR, boolean hashSeed) {
        MessageDigest hashAlg;
        try {
            hashAlg = MessageDigest.getInstance(params.hashAlg);
        } catch (NoSuchAlgorithmException e) {
            throw new NtruException(e);
        }
        
        int hashLen = hashAlg.getDigestLength();
        ByteBuffer buf = ByteBuffer.allocate(minCallsR*hashLen);
        byte[] Z = hashSeed ? hashAlg.digest(seed) : seed;
        int counter = 0;
        while (counter < minCallsR) {
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
        int pkLen = params.pkLen;
        int minCallsMask = params.minCallsMask;
        boolean hashSeed = params.hashSeed;
        byte[] oid = params.oid;
        
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
        
        IntegerPolynomial cR = e.clone();
        cR.sub(ci);
        cR.modPositive(q);
        IntegerPolynomial cR4 = cR.clone();
        cR4.modPositive(4);
        byte[] coR4 = cR4.toBinary(4);
        IntegerPolynomial mask = MGF(coR4, N, minCallsMask, hashSeed);
        IntegerPolynomial cMTrin = ci;
        cMTrin.sub(mask);
        cMTrin.mod3();
        byte[] cM = cMTrin.toBinary3Sves();
        
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
        
        // sData = OID|m|b|hTrunc
        byte[] bh = pub.toBinary(q);
        byte[] hTrunc = Arrays.copyOf(bh, pkLen/8);
        ByteBuffer sDataBuffer = ByteBuffer.allocate(oid.length + cl + cb.length + hTrunc.length);
        sDataBuffer.put(oid);
        sDataBuffer.put(cm);
        sDataBuffer.put(cb);
        sDataBuffer.put(hTrunc);
        byte[] sData = sDataBuffer.array();
        
        Polynomial cr = generateBlindingPoly(sData, cm);
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
        IntegerPolynomial a;
        if (params.fastFp) {
            a = priv_t.mult(e, params.q);
            a.mult(3);
            a.add(e);
        }
        else
            a = priv_t.mult(e, params.q);
        a.center0(params.q);
        a.mod3();
        
        IntegerPolynomial c = params.fastFp ? a : new DenseTernaryPolynomial(a).mult(priv_fp, 3);
        c.center0(3);
        return c;
    }
}