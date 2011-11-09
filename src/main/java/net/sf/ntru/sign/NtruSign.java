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

package net.sf.ntru.sign;

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.ZERO;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import net.sf.ntru.arith.BigIntEuclidean;
import net.sf.ntru.exception.NtruException;
import net.sf.ntru.polynomial.BigDecimalPolynomial;
import net.sf.ntru.polynomial.BigIntPolynomial;
import net.sf.ntru.polynomial.DenseTernaryPolynomial;
import net.sf.ntru.polynomial.IntegerPolynomial;
import net.sf.ntru.polynomial.Polynomial;
import net.sf.ntru.polynomial.ProductFormPolynomial;
import net.sf.ntru.polynomial.Resultant;
import net.sf.ntru.sign.SignatureParameters.BasisType;
import net.sf.ntru.sign.SignatureParameters.KeyGenAlg;
import net.sf.ntru.sign.SignatureParameters.TernaryPolynomialType;
import net.sf.ntru.sign.SignaturePrivateKey.Basis;

/**
 * Signs, verifies data and generates key pairs.
 */
public class NtruSign {
    private SignatureParameters params;
    private MessageDigest hashAlg;
    private SignatureKeyPair signingKeyPair;
    private SignaturePublicKey verificationKey;
    
    /**
     * Constructs a new instance with a set of signature parameters.
     * @param params signature parameters
     */
    public NtruSign(SignatureParameters params) {
        this.params = params;
    }
    
    /**
     * Generates a new signature key pair. Starts <code>B+1</code> threads.
     * @return a key pair
     */
    public SignatureKeyPair generateKeyPair() {
        SignaturePrivateKey priv = new SignaturePrivateKey();
        SignaturePublicKey pub = null;
        ExecutorService executor = Executors.newCachedThreadPool();
        List<Future<Basis>> bases = new ArrayList<Future<Basis>>();
        for (int k=params.B; k>=0; k--)
            bases.add(executor.submit(new BasisGenerationTask()));
        executor.shutdown();
        
        for (int k=params.B; k>=0; k--) {
            Future<Basis> basis = bases.get(k);
            try {
                priv.add(basis.get());
            if (k == 0)
                pub = new SignaturePublicKey(basis.get().h, params);
            } catch (Exception e) {
                throw new NtruException(e);
            }
        }
        SignatureKeyPair kp = new SignatureKeyPair(priv, pub);
        return kp;
    }

    /**
     * Generates a new signature key pair. Runs in a single thread.
     * @return a key pair
     */
    public SignatureKeyPair generateKeyPairSingleThread() {
        SignaturePrivateKey priv = new SignaturePrivateKey();
        SignaturePublicKey pub = null;
        for (int k=params.B; k>=0; k--) {
            Basis basis = generateBoundedBasis();
            priv.add(basis);
            if (k == 0)
                pub = new SignaturePublicKey(basis.h, params);
        }
        SignatureKeyPair kp = new SignatureKeyPair(priv, pub);
        return kp;
    }

    /**
     * Resets the engine for signing a message.
     * @param kp
     * @throws NtruException if the JRE doesn't implement the specified hash algorithm
     */
    public void initSign(SignatureKeyPair kp) {
        this.signingKeyPair = kp;
        try {
            hashAlg = MessageDigest.getInstance(params.hashAlg);
        } catch (NoSuchAlgorithmException e) {
            throw new NtruException(e);
        }
        hashAlg.reset();
    }

    /**
     * Adds data to sign or verify.
     * @param m
     * @throws NtruException if <code>initSign</code> was not called
     */
    public void update(byte[] m) {
        if (hashAlg == null)
            throw new NtruException("Call initSign or initVerify first!");
        
        hashAlg.update(m);
    }
    
    /**
     * Adds data to sign and computes a signature over this data and any data previously added via {@link #update(byte[])}.
     * @param m
     * @return a signature
     * @throws NtruException if <code>initSign</code> was not called
     */
    public byte[] sign(byte[] m) {
        if (hashAlg==null || signingKeyPair==null)
            throw new NtruException("Call initSign first!");
        
        byte[] msgHash;
        msgHash = hashAlg.digest(m);
        return signHash(msgHash, signingKeyPair);
    }
    
    /**
     * Signs a message.<br/>
     * This is a "one stop" method and does not require <code>initSign</code> to be called. Only the message supplied via
     * the parameter <code>m</code> is signed, regardless of prior calls to {@link #update(byte[])}.
     * @param m the message to sign
     * @param kp a key pair (the public key is needed to ensure there are no signing failures)
     * @return a signature
     * @throws NtruException if the JRE doesn't implement the specified hash algorithm
     */
    public byte[] sign(byte[] m, SignatureKeyPair kp) {
        try {
            // EESS directly passes the message into the MRGM (message representative
            // generation method). Since that is inefficient for long messages, we work
            // with the hash of the message.
            byte[] msgHash = MessageDigest.getInstance(params.hashAlg).digest(m);
            return signHash(msgHash, kp);
        } catch (NoSuchAlgorithmException e) {
            throw new NtruException(e);
        }
    }
    
    private byte[] signHash(byte[] msgHash, SignatureKeyPair kp) {
        int r = 0;
        IntegerPolynomial s;
        IntegerPolynomial i;
        do {
            r++;
            if (r > params.signFailTolerance)
                throw new NtruException("Signing failed: too many retries (max=" + params.signFailTolerance + ")");
            i = createMsgRep(msgHash, r);
            s = sign(i, kp);
        } while (!verify(i, s, kp.pub.h));

        byte[] rawSig = s.toBinary(params.q);
        ByteBuffer sbuf = ByteBuffer.allocate(rawSig.length + 4);
        sbuf.put(rawSig);
        sbuf.putInt(r);
        return sbuf.array();
    }
    
    private IntegerPolynomial sign(IntegerPolynomial i, SignatureKeyPair kp) {
        int N = params.N;
        int q = params.q;
        int perturbationBases = params.B;
        
        IntegerPolynomial s = new IntegerPolynomial(N);
        int iLoop = perturbationBases;
        while (iLoop >= 1) {
            Polynomial f = kp.priv.getBasis(iLoop).f;
            Polynomial fPrime = kp.priv.getBasis(iLoop).fPrime;
            
            IntegerPolynomial y = f.mult(i);
            y.div(q);
            y = fPrime.mult(y);
            
            IntegerPolynomial x = fPrime.mult(i);
            x.div(q);
            x = f.mult(x);

            IntegerPolynomial si = y;
            si.sub(x);
            s.add(si);
            
            IntegerPolynomial hi = kp.priv.getBasis(iLoop).h.clone();
            if (iLoop > 1)
                hi.sub(kp.priv.getBasis(iLoop-1).h);
            else
                hi.sub(kp.pub.h);
            i = si.mult(hi, q);
            
            iLoop--;
        }
        
        Polynomial f = kp.priv.getBasis(0).f;
        Polynomial fPrime = kp.priv.getBasis(0).fPrime;
        
        IntegerPolynomial y = f.mult(i);
        y.div(q);
        y = fPrime.mult(y);
        
        IntegerPolynomial x = fPrime.mult(i);
        x.div(q);
        x = f.mult(x);

        y.sub(x);
        s.add(y);
        s.modPositive(q);
        return s;
    }
    
    /**
     * Resets the engine for verifying a signature.
     * @param pub the public key to use in the {@link #verify(byte[])} step
     * @throws NtruException if the JRE doesn't implement the specified hash algorithm
     */
    public void initVerify(SignaturePublicKey pub) {
        verificationKey = pub;
        try {
            hashAlg = MessageDigest.getInstance(params.hashAlg);
        } catch (NoSuchAlgorithmException e) {
            throw new NtruException(e);
        }
        hashAlg.reset();
    }

    /**
     * Verifies a signature for any data previously added via {@link #update(byte[])}.
     * @param sig a signature
     * @return whether the signature is valid
     * @throws NtruException if <code>initVerify</code> was not called
     */
    public boolean verify(byte[] sig) {
        if (hashAlg==null || verificationKey==null)
            throw new NtruException("Call initVerify first!");
        
        byte[] msgHash = hashAlg.digest();
        return verifyHash(msgHash, sig, verificationKey);
    }
    
    /**
     * Verifies a signature.<br/>
     * This is a "one stop" method and does not require <code>initVerify</code> to be called. Only the message supplied via
     * the parameter <code>m</code> is signed, regardless of prior calls to {@link #update(byte[])}.
     * @param m the message to sign
     * @param sig the signature
     * @param pub a public key
     * @return whether the signature is valid
     * @throws NtruException if the JRE doesn't implement the specified hash algorithm
     */
    public boolean verify(byte[] m, byte[] sig, SignaturePublicKey pub) {
        try {
            byte[] msgHash = MessageDigest.getInstance(params.hashAlg).digest(m);
            return verifyHash(msgHash, sig, pub);
        } catch (NoSuchAlgorithmException e) {
            throw new NtruException(e);
        }
    }
    
    private boolean verifyHash(byte[] msgHash, byte[] sig, SignaturePublicKey pub) {
        ByteBuffer sbuf = ByteBuffer.wrap(sig);
        byte[] rawSig = new byte[sig.length - 4];
        sbuf.get(rawSig);
        IntegerPolynomial s = IntegerPolynomial.fromBinary(rawSig, params.N, params.q);
        int r = sbuf.getInt();
        return verify(createMsgRep(msgHash, r), s, pub.h);
    }
    
    private boolean verify(IntegerPolynomial i, IntegerPolynomial s, IntegerPolynomial h) {
        int q = params.q;
        double normBoundSq = params.normBoundSq;
        double betaSq = params.betaSq;
        
        IntegerPolynomial t = h.mult(s, q);
        t.sub(i);
        long centeredNormSq = (long)(s.centeredNormSq(q) + betaSq * t.centeredNormSq(q));
        return centeredNormSq <= normBoundSq;
    }
    
    IntegerPolynomial createMsgRep(byte[] msgHash, int r) {
        int N = params.N;
        int q = params.q;
        
        int c = 31 - Integer.numberOfLeadingZeros(q);
        int B = (c+7) / 8;
        IntegerPolynomial i = new IntegerPolynomial(N);
        
        ByteBuffer cbuf = ByteBuffer.allocate(msgHash.length + 4);
        cbuf.put(msgHash);
        cbuf.putInt(r);
        Prng prng = new Prng(cbuf.array(), params.hashAlg);
        
        for (int t=0; t<N; t++) {
            byte[] o = prng.nextBytes(B);
            int hi = o[o.length-1];
            hi >>= 8*B-c;
            hi <<= 8*B-c;
            o[o.length-1] = (byte)hi;
            
            ByteBuffer obuf = ByteBuffer.allocate(4);
            obuf.put(o);
            obuf.rewind();
            // reverse byte order so it matches the endianness of java ints
            i.coeffs[t] = Integer.reverseBytes(obuf.getInt());
        }
        return i;
    }
    
    /**
     * Creates a basis such that <code>|F| &lt; keyNormBound</code> and <code>|G| &lt; keyNormBound</code>
     * @return a NtruSign basis
     */
    Basis generateBoundedBasis() {
        while (true) {
            FGBasis basis = generateBasis();
            if (basis.isNormOk())
                return basis;
        }
    }
    
    /**
     * Creates a NtruSign basis consisting of polynomials <code>f, g, F, G, h</code>.<br/>
     * If <code>KeyGenAlg=FLOAT</code>, the basis may not be valid and this method must be rerun if that is the case.<br/>
     * @see #generateBoundedBasis()
     */
    private FGBasis generateBasis() {
        int N = params.N;
        int q = params.q;
        int d = params.d;
        int d1 = params.d1;
        int d2 = params.d2;
        int d3 = params.d3;
        BasisType basisType = params.basisType;
        
        Polynomial f;
        IntegerPolynomial fInt;
        Polynomial g;
        IntegerPolynomial gInt;
        IntegerPolynomial fq;
        Resultant rf;
        Resultant rg;
        BigIntEuclidean r;
        
        int _2n1 = 2*N+1;
        boolean primeCheck = params.primeCheck;
        
        do {
            do {
                f = params.polyType==TernaryPolynomialType.SIMPLE ? DenseTernaryPolynomial.generateRandom(N, d+1, d) : ProductFormPolynomial.generateRandom(N, d1, d2, d3+1, d3);
                fInt = f.toIntegerPolynomial();
            } while (primeCheck && fInt.resultant(_2n1).res.equals(ZERO));
            fq = fInt.invertFq(q);
        } while (fq == null);
        rf = fInt.resultant(); 
        
        do {
            do {
                do {
                    g = params.polyType==TernaryPolynomialType.SIMPLE ? DenseTernaryPolynomial.generateRandom(N, d+1, d) : ProductFormPolynomial.generateRandom(N, d1, d2, d3+1, d3);
                    gInt = g.toIntegerPolynomial();
                } while (primeCheck && gInt.resultant(_2n1).res.equals(ZERO));
            } while (gInt.invertFq(q) == null);
            rg = gInt.resultant();
            r = BigIntEuclidean.calculate(rf.res, rg.res);
        } while (!r.gcd.equals(ONE));
        
        BigIntPolynomial A = rf.rho.clone();
        A.mult(r.x.multiply(BigInteger.valueOf(q)));
        BigIntPolynomial B = rg.rho.clone();
        B.mult(r.y.multiply(BigInteger.valueOf(-q)));
        
        BigIntPolynomial C;
        if (params.keyGenAlg == KeyGenAlg.RESULTANT) {
            int[] fRevCoeffs = new int[N];
            int[] gRevCoeffs = new int[N];
            fRevCoeffs[0] = fInt.coeffs[0];
            gRevCoeffs[0] = gInt.coeffs[0];
            for (int i=1; i<N; i++) {
                fRevCoeffs[i] = fInt.coeffs[N-i];
                gRevCoeffs[i] = gInt.coeffs[N-i];
            }
            IntegerPolynomial fRev = new IntegerPolynomial(fRevCoeffs);
            IntegerPolynomial gRev = new IntegerPolynomial(gRevCoeffs);
            
            IntegerPolynomial t = f.mult(fRev);
            t.add(g.mult(gRev));
            Resultant rt = t.resultant();
            C = fRev.mult(B);   // fRev.mult(B) is actually faster than new SparseTernaryPolynomial(fRev).mult(B), possibly due to cache locality?
            C.add(gRev.mult(A));
            C = C.multBig(rt.rho);
            C.div(rt.res);
        }
        else {   // KeyGenAlg.FLOAT
            // calculate ceil(log10(N))
            int log10N = 0;
            for (int i=1; i<N; i*=10)
                log10N++;
            
            // * Cdec needs to be accurate to 1 decimal place so it can be correctly rounded;
            // * fInv loses up to (#digits of longest coeff of B) places in fInv.mult(B);
            // * multiplying fInv by B also multiplies the rounding error by a factor of N;
            // so make #decimal places of fInv the sum of the above.
            BigDecimalPolynomial fInv = rf.rho.div(new BigDecimal(rf.res), B.getMaxCoeffLength()+1+log10N);
            BigDecimalPolynomial gInv = rg.rho.div(new BigDecimal(rg.res), A.getMaxCoeffLength()+1+log10N);
            
            BigDecimalPolynomial Cdec = fInv.mult(B);
            Cdec.add(gInv.mult(A));
            Cdec.halve();
            C = Cdec.round();
        }
        
        BigIntPolynomial F = B.clone();
        F.sub(f.mult(C));
        BigIntPolynomial G = A.clone();
        G.sub(g.mult(C));

        IntegerPolynomial FInt = new IntegerPolynomial(F);
        IntegerPolynomial GInt = new IntegerPolynomial(G);
        minimizeFG(fInt, gInt, FInt, GInt, N);
        
        Polynomial fPrime;
        IntegerPolynomial h;
        if (basisType == BasisType.STANDARD) {
            fPrime = FInt;
            h = g.mult(fq, q);
        }
        else {
            fPrime = g;
            h = FInt.mult(fq, q);
        }
        h.modPositive(q);
        
        return new FGBasis(f, fPrime, h, FInt, GInt, params);
    }
    
    /**
     * Implementation of the optional steps 20 through 26 in EESS1v2.pdf, section 3.5.1.1.
     * This doesn't seem to have much of an effect and sometimes actually increases the
     * norm of F, but on average it slightly reduces the norm.<br/>
     * This method changes <code>F</code> and <code>g</code> but leaves <code>f</code> and
     * <code>g</code> unchanged.
     * @param f
     * @param g
     * @param F
     * @param G
     * @param N
     */
    private void minimizeFG(IntegerPolynomial f, IntegerPolynomial g, IntegerPolynomial F, IntegerPolynomial G, int N) {
        int E = 0;
        for (int j=0; j<N; j++)
            E += 2 * N * (f.coeffs[j]*f.coeffs[j] + g.coeffs[j]*g.coeffs[j]);
        
        // [f(1)+g(1)]^2 = 4
        E -= 4;
        
        IntegerPolynomial u = f.clone();
        IntegerPolynomial v = g.clone();
        int j = 0;
        int k = 0;
        int maxAdjustment = N;
        while (k<maxAdjustment && j<N) {
            int D = 0;
            int i = 0;
            while (i < N) {
                int D1 = F.coeffs[i] * f.coeffs[i];
                int D2 = G.coeffs[i] * g.coeffs[i];
                int D3 = 4 * N * (D1+D2);
                D += D3;
                i++;
            }
            // f(1)+g(1) = 2
            int D1 = 4 * (F.sumCoeffs() + G.sumCoeffs());
            D -= D1;
            
            if (D > E) {
                F.sub(u);
                G.sub(v);
                k++;
                j = 0;
            }
            else if (D < -E) {
                F.add(u);
                G.add(v);
                k++;
                j = 0;
            }
            j++;
            u.rotate1();
            v.rotate1();
        }
    }
    
    private class BasisGenerationTask implements Callable<Basis> {

        @Override
        public Basis call() throws Exception {
            return generateBoundedBasis();
        }
    }
    
    /**
     * A subclass of Basis that additionally contains the polynomials <code>F</code> and <code>G</code>.
     */
    class FGBasis extends Basis {
        IntegerPolynomial F, G;
        
        FGBasis(Polynomial f, Polynomial fPrime, IntegerPolynomial h, IntegerPolynomial F, IntegerPolynomial G, SignatureParameters params) {
            super(f, fPrime, h, params);
            this.F = F;
            this.G = G;
        }
        
        /**
         * Returns <code>true</code> if the norms of the polynomials <code>F</code> and <code>G</code>
         * are within {@link SignatureParameters#keyNormBound}.
         * @return
         */
        boolean isNormOk() {
            double keyNormBoundSq = params.keyNormBoundSq;
            int q = params.q;
            return (F.centeredNormSq(q)<keyNormBoundSq && G.centeredNormSq(q)<keyNormBoundSq);
        }
    }
}