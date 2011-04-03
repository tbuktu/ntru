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

import java.math.BigInteger;
import java.nio.ByteBuffer;
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
    
    /** Uses B+1 threads */
    public static SignatureKeyPair generateKeyPair(SignatureParameters params) {
        SignaturePrivateKey priv = new SignaturePrivateKey();
        SignaturePublicKey pub = null;
        ExecutorService executor = Executors.newCachedThreadPool();
        List<Future<Basis>> bases = new ArrayList<Future<Basis>>();
        for (int k=params.B; k>=0; k--)
            bases.add(executor.submit(new BasisGenerationTask(params)));
        
        for (int k=params.B; k>=0; k--) {
            Future<Basis> basis = bases.get(k);
            try {
                priv.add(basis.get());
            if (k == 0)
                pub = new SignaturePublicKey(basis.get().h, params);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        SignatureKeyPair kp = new SignatureKeyPair(priv, pub);
        return kp;
    }

    public static SignatureKeyPair generateKeyPairSingleThread(SignatureParameters params) {
        SignaturePrivateKey priv = new SignaturePrivateKey();
        SignaturePublicKey pub = null;
        for (int k=params.B; k>=0; k--) {
            Basis basis = createBasis(params);
            priv.add(basis);
            if (k == 0)
                pub = new SignaturePublicKey(basis.h, params);
        }
        SignatureKeyPair kp = new SignatureKeyPair(priv, pub);
        return kp;
    }

    public static byte[] sign(byte[] m, SignaturePrivateKey priv, SignaturePublicKey pub, SignatureParameters params) {
        int r = 0;
        IntegerPolynomial s;
        IntegerPolynomial i;
        do {
            r++;
            try {
                i = createMsgRep(m, r, params);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
            s = sign(i, priv, pub, params);
        } while (!verify(i, s, pub.h, params));

        byte[] rawSig = s.toBinary(params.q);
        ByteBuffer sbuf = ByteBuffer.allocate(rawSig.length + 4);
        sbuf.put(rawSig);
        sbuf.putInt(r);
        return sbuf.array();
    }
    
    static IntegerPolynomial sign(IntegerPolynomial i, SignaturePrivateKey priv, SignaturePublicKey pub, SignatureParameters params) {
        int N = params.N;
        int q = params.q;
        int perturbationBases = params.B;
        
        IntegerPolynomial s = new IntegerPolynomial(N);
        int iLoop = perturbationBases;
        while (iLoop >= 1) {
            IntegerPolynomial f = priv.getBasis(iLoop).f;
            IntegerPolynomial fPrime = priv.getBasis(iLoop).fPrime;
            
            IntegerPolynomial y = i.mult(f);
            y.div(q);
            y = y.mult(fPrime);
            
            IntegerPolynomial x = i.mult(fPrime);
            x.div(q);
            x = x.mult(f);

            IntegerPolynomial si = y;
            si.sub(x);
            s.add(si);
            
            IntegerPolynomial hi = priv.getBasis(iLoop).h.clone();
            if (iLoop > 1)
                hi.sub(priv.getBasis(iLoop-1).h);
            else
                hi.sub(pub.h);
            i = si.mult(hi, q);
            
            iLoop--;
        }
        
        IntegerPolynomial f = priv.getBasis(0).f;
        IntegerPolynomial fPrime = priv.getBasis(0).fPrime;
        
        IntegerPolynomial y = i.mult(f);
        y.div(q);
        y = y.mult(fPrime);
        
        IntegerPolynomial x = i.mult(fPrime);
        x.div(q);
        x = x.mult(f);

        y.sub(x);
        s.add(y);
        s.modPositive(q);
        return s;
    }
    
    public static boolean verify(byte[] m, byte[] sig, SignaturePublicKey pub, SignatureParameters params) {
        ByteBuffer sbuf = ByteBuffer.wrap(sig);
        byte[] rawSig = new byte[sig.length - 4];
        sbuf.get(rawSig);
        IntegerPolynomial s = IntegerPolynomial.fromBinary(rawSig, params.N, params.q);
        int r = sbuf.getInt();
        try {
            return verify(createMsgRep(m, r, params), s, pub.h, params);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    
    static boolean verify(IntegerPolynomial i, IntegerPolynomial s, IntegerPolynomial h, SignatureParameters params) {
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
    
    static IntegerPolynomial createMsgRep(byte[] m, int r, SignatureParameters params) throws NoSuchAlgorithmException {
        int N = params.N;
        int q = params.q;
        
        int c = 31 - Integer.numberOfLeadingZeros(q);
        int B = (c+7) / 8;
        IntegerPolynomial i = new IntegerPolynomial(N);
        
        ByteBuffer cbuf = ByteBuffer.allocate(m.length + 4);
        cbuf.put(m);
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
    
    private static Basis createBasis(SignatureParameters params) {
        int N = params.N;
        int q = params.q;
        int d = params.d;
        BasisType basisType = params.basisType;
        
        IntegerPolynomial f;
        IntegerPolynomial g;
        IntegerPolynomial fq;
        Resultant rf;
        Resultant rg;
        BigIntEuclidean r;
        
        int _2n1 = 2*N+1;
        boolean primeCheck = params.primeCheck;
        
        do {
            f = IntegerPolynomial.generateRandomSmall(N, d+1, d);
            fq = f.invertFq(q);
        } while (fq == null);
        rf = f.resultant();
        
        do {
            do {
                g = IntegerPolynomial.generateRandomSmall(N, d+1, d);
            } while (primeCheck && f.resultant(_2n1).res.equals(ZERO) && g.resultant(_2n1).res.equals(ZERO));
            rg = g.resultant();
            r = BigIntEuclidean.calculate(rf.res, rg.res);
        } while (!r.gcd.equals(ONE));
        
        BigIntPolynomial F = rg.rho;
        F.mult(r.y.negate().multiply(BigInteger.valueOf(q)));
        BigIntPolynomial G = rf.rho;
        G.mult(r.x.multiply(BigInteger.valueOf(q)));
        
        int[] fRevCoeffs = new int[N];
        int[] gRevCoeffs = new int[N];
        fRevCoeffs[0] = f.coeffs[0];
        gRevCoeffs[0] = g.coeffs[0];
        for (int i=1; i<N; i++) {
            fRevCoeffs[i] = f.coeffs[N-i];
            gRevCoeffs[i] = g.coeffs[N-i];
        }
        IntegerPolynomial fRev = new IntegerPolynomial(fRevCoeffs);
        IntegerPolynomial gRev = new IntegerPolynomial(gRevCoeffs);
        
        IntegerPolynomial t = f.mult(fRev);
        t.add(g.mult(gRev));
        Resultant rt = t.resultant();
        BigIntPolynomial c = F.mult(fRev);
        c.add(G.mult(gRev));
        c = c.mult(rt.rho);
        c.div(rt.res);
        F.sub(c.mult(f));
        G.sub(c.mult(g));

        if (!equalsQ(f, g, F, G, q, N))
            throw new RuntimeException("this shouldn't happen");
        
        IntegerPolynomial fPrime;
        IntegerPolynomial h;
        if (basisType == BasisType.STANDARD) {
            fPrime = new IntegerPolynomial(F);
            h = g.mult(fq, q);
        }
        else {
            fPrime = g;
            h = new IntegerPolynomial(F).mult(fq, q);
        }
        h.modPositive(q);
        
        return new Basis(f, fPrime, h, params);
    }
    
    // verifies that f*G-g*F=q
    private static boolean equalsQ(IntegerPolynomial f, IntegerPolynomial g, BigIntPolynomial F, BigIntPolynomial G, int q, int N) {
        G = new BigIntPolynomial(java.util.Arrays.copyOf(G.coeffs, N));
        BigIntPolynomial x = new BigIntPolynomial(f).mult(G);
        x.sub(new BigIntPolynomial(g).mult(F));
        boolean equalsQ=true;
        for (int i=1; i<x.coeffs.length-1; i++)
            equalsQ &= ZERO.equals(x.coeffs[i]);
        equalsQ &= x.coeffs[0].equals(BigInteger.valueOf(q));
        return equalsQ;
    }
    
    private static class BasisGenerationTask implements Callable<Basis> {
        private SignatureParameters params;
        
        private BasisGenerationTask(SignatureParameters params) {
            this.params = params;
        }

        @Override
        public Basis call() throws Exception {
            return createBasis(params);
        }
    }
}