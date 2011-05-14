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

import net.sf.ntru.SignatureParameters.BasisType;
import net.sf.ntru.SignaturePrivateKey.Basis;

public class NtruSign {
    private SignatureParameters params;
    private MessageDigest hashAlg;
    private SignatureKeyPair signingKeyPair;
    private SignaturePublicKey verificationKey;
    
    public NtruSign(SignatureParameters params) {
        this.params = params;
    }
    
    /** Uses B+1 threads */
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

    public SignatureKeyPair generateKeyPairSingleThread() {
        SignaturePrivateKey priv = new SignaturePrivateKey();
        SignaturePublicKey pub = null;
        for (int k=params.B; k>=0; k--) {
            Basis basis = createBasis();
            priv.add(basis);
            if (k == 0)
                pub = new SignaturePublicKey(basis.h, params);
        }
        SignatureKeyPair kp = new SignatureKeyPair(priv, pub);
        return kp;
    }

    public void initSign(SignatureKeyPair kp) {
        this.signingKeyPair = kp;
        try {
            hashAlg = MessageDigest.getInstance("SHA-512");
        } catch (NoSuchAlgorithmException e) {
            throw new NtruException(e);
        }
        hashAlg.reset();
    }

    public void update(byte[] m) {
        if (hashAlg == null)
            throw new NtruException("Call initSign or initVerify first!");
        
        hashAlg.update(m);
    }
    
    public byte[] sign(byte[] m) {
        if (hashAlg==null || signingKeyPair==null)
            throw new NtruException("Call initSign first!");
        
        byte[] msgHash;
        msgHash = hashAlg.digest(m);
        return signHash(msgHash, signingKeyPair);
    }
    
    public byte[] sign(byte[] m, SignatureKeyPair kp) {
        try {
            // EESS directly passes the message into the MRGM (message representative
            // generation method). Since that is inefficient for long messages, we work
            // with the hash of the message.
            byte[] msgHash = MessageDigest.getInstance("SHA-512").digest(m);
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
            try {
                i = createMsgRep(msgHash, r);
            } catch (NoSuchAlgorithmException e) {
                throw new NtruException(e);
            }
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
            TernaryPolynomial f = kp.priv.getBasis(iLoop).f;
            IntegerPolynomial fPrime = kp.priv.getBasis(iLoop).fPrime;
            
            IntegerPolynomial y = f.mult(i);
            y.div(q);
            y = y.mult(fPrime);
            
            IntegerPolynomial x = i.mult(fPrime);
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
        
        TernaryPolynomial f = kp.priv.getBasis(0).f;
        IntegerPolynomial fPrime = kp.priv.getBasis(0).fPrime;
        
        IntegerPolynomial y = f.mult(i);
        y.div(q);
        y = y.mult(fPrime);
        
        IntegerPolynomial x = i.mult(fPrime);
        x.div(q);
        x = f.mult(x);

        y.sub(x);
        s.add(y);
        s.modPositive(q);
        return s;
    }
    
    public void initVerify(SignaturePublicKey pub) {
        verificationKey = pub;
        try {
            hashAlg = MessageDigest.getInstance("SHA-512");
        } catch (NoSuchAlgorithmException e) {
            throw new NtruException(e);
        }
        hashAlg.reset();
    }

    public boolean verify(byte[] sig) {
        if (hashAlg==null || verificationKey==null)
            throw new NtruException("Call initVerify first!");
        
        byte[] msgHash = hashAlg.digest();
        return verifyHash(msgHash, sig, verificationKey);
    }
    
    public boolean verify(byte[] m, byte[] sig, SignaturePublicKey pub) {
        try {
            byte[] msgHash = MessageDigest.getInstance("SHA-512").digest(m);
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
        try {
            return verify(createMsgRep(msgHash, r), s, pub.h);
        } catch (NoSuchAlgorithmException e) {
            throw new NtruException(e);
        }
    }
    
    boolean verify(IntegerPolynomial i, IntegerPolynomial s, IntegerPolynomial h) {
        int N = params.N;
        int q = params.q;
        double normBoundSq = params.normBoundSq;
        double betaSq = params.betaSq;
        
        IntegerPolynomial t = h.mult(s, q);
        t.sub(i);

        t.shiftGap(q);
        s = s.clone();
        s.shiftGap(q);
        
        long ssum = 0;
        long s2sum = 0;
        long tsum = 0;
        long t2sum = 0;
        for (int j=0; j<N; j++) {
            int sj = s.coeffs[j];
            ssum += sj;
            s2sum += sj * sj;
            int tj = t.coeffs[j];
            tsum += tj;
            t2sum += tj * tj;
        }
        long centeredNormSq = s2sum - ssum*ssum/N;
        centeredNormSq += (long)(betaSq * (t2sum - tsum*tsum/N));
        
        return centeredNormSq <= normBoundSq;
    }
    
    IntegerPolynomial createMsgRep(byte[] msgHash, int r) throws NoSuchAlgorithmException {
        int N = params.N;
        int q = params.q;
        
        int c = 31 - Integer.numberOfLeadingZeros(q);
        int B = (c+7) / 8;
        IntegerPolynomial i = new IntegerPolynomial(N);
        
        ByteBuffer cbuf = ByteBuffer.allocate(msgHash.length + 4);
        cbuf.put(msgHash);
        cbuf.putInt(r);
        Prng prng = new Prng(cbuf.array());
        
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
    
    private Basis createBasis() {
        int N = params.N;
        int q = params.q;
        int d = params.d;
        BasisType basisType = params.basisType;
        int decimalPlaces = params.keyGenerationDecimalPlaces;
        
        DenseTernaryPolynomial f;
        IntegerPolynomial g;
        IntegerPolynomial fq;
        Resultant rf;
        Resultant rg;
        BigIntEuclidean r;
        
        int _2n1 = 2*N+1;
        boolean primeCheck = params.primeCheck;
        
        do {
            f = DenseTernaryPolynomial.generateRandom(N, d+1, d);
            fq = f.invertFq(q);
        } while (fq == null);
        rf = f.resultant();
        
        do {
            do {
                do {
                    g = DenseTernaryPolynomial.generateRandom(N, d+1, d);
                } while (primeCheck && f.resultant(_2n1).res.equals(ZERO) && g.resultant(_2n1).res.equals(ZERO));
            } while (g.invertFq(q) == null);
            rg = g.resultant();
            r = BigIntEuclidean.calculate(rf.res, rg.res);
        } while (!r.gcd.equals(ONE));
        
        BigIntPolynomial A = rf.rho.clone();
        A.mult(r.x.multiply(BigInteger.valueOf(q)));
        BigIntPolynomial B = rg.rho.clone();
        B.mult(r.y.multiply(BigInteger.valueOf(-q)));
        
        BigDecimalPolynomial fInv = rf.rho.div(new BigDecimal(rf.res), decimalPlaces);
        BigDecimalPolynomial gInv = rg.rho.div(new BigDecimal(rg.res), decimalPlaces);
        
        BigDecimalPolynomial Cdec = fInv.mult(B);
        Cdec.add(gInv.mult(A));
        Cdec.halve();
        BigIntPolynomial C = Cdec.round();
        
        BigIntPolynomial F = B.clone();
        // always use sparse multiplication here
        TernaryPolynomial fTer = new SparseTernaryPolynomial(f);
        F.sub(fTer.mult(C));
        BigIntPolynomial G = A.clone();
        TernaryPolynomial gTer = new SparseTernaryPolynomial(g);
        G.sub(gTer.mult(C));

        IntegerPolynomial FInt=new IntegerPolynomial(F);
        IntegerPolynomial GInt=new IntegerPolynomial(G);
        minimizeFG(f, g, FInt, GInt, N);
        
        if (!equalsQ(f, g, F, G, q, N))
            throw new NtruException("this shouldn't happen");
        
        IntegerPolynomial fPrime;
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
        
        return new Basis(fTer, fPrime, h, params);
    }
    
    /**
     * Implementation of the optional steps 20 through 26 in EESS1v2.pdf, section 3.5.1.1.
     * This doesn't seem to have much of an effect, and sometimes actually increases the
     * norm of F, but on average it slightly reduces the norm.
     * @param params
     * @return
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
    
    // verifies that f*G-g*F=q
    private boolean equalsQ(IntegerPolynomial f, IntegerPolynomial g, BigIntPolynomial F, BigIntPolynomial G, int q, int N) {
        G = new BigIntPolynomial(java.util.Arrays.copyOf(G.coeffs, N));
        BigIntPolynomial x = new BigIntPolynomial(f).mult(G);
        x.sub(new BigIntPolynomial(g).mult(F));
        boolean equalsQ=true;
        for (int i=1; i<x.coeffs.length-1; i++)
            equalsQ &= ZERO.equals(x.coeffs[i]);
        equalsQ &= x.coeffs[0].equals(BigInteger.valueOf(q));
        return equalsQ;
    }
    
    private class BasisGenerationTask implements Callable<Basis> {

        @Override
        public Basis call() throws Exception {
            return createBasis();
        }
    }
}