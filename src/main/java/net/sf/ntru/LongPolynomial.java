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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

class LongPolynomial {
    // prime numbers > 3*10^9
    private static final long[] PRIMES = new long[] {
        3000000019L, 3000000037L, 3000000077L, 3000000109L, 3000000151L, 3000000209L, 
        3000000253L, 3000000257L, 3000000277L, 3000000343L, 3000000347L, 3000000349L, 
        3000000361L, 3000000371L, 3000000391L, 3000000397L, 3000000401L, 3000000403L, 
        3000000407L, 3000000433L, 3000000457L, 3000000461L, 3000000473L, 3000000511L, 
        3000000517L, 3000000539L, 3000000551L, 3000000571L, 3000000583L, 3000000593L, 
        3000000599L, 3000000673L, 3000000713L, 3000000749L, 3000000781L, 3000000803L, 
        3000000821L, 3000000827L, 3000000833L, 3000000889L, 3000000967L, 3000000973L, 
        3000001003L, 3000001031L, 3000001049L, 3000001057L, 3000001087L, 3000001093L, 
        3000001139L, 3000001153L, 3000001171L, 3000001177L, 3000001183L, 3000001229L, 
        3000001259L, 3000001267L, 3000001307L, 3000001321L, 3000001331L, 3000001337L, 
        3000001387L, 3000001427L, 3000001507L, 3000001513L, 3000001549L, 3000001567L, 
        3000001579L, 3000001583L, 3000001601L, 3000001603L, 3000001621L, 3000001633L, 
        3000001639L, 3000001651L, 3000001661L, 3000001663L, 3000001691L, 3000001709L, 
        3000001721L, 3000001723L, 3000001783L, 3000001801L, 3000001811L, 3000001817L, 
        3000001867L, 3000001891L, 3000001897L, 3000001931L, 3000001957L, 3000001993L, 
        3000001997L, 3000002003L, 3000002051L, 3000002077L, 3000002107L, 3000002119L, 
        3000002141L, 3000002147L, 3000002149L, 3000002183L, 3000002197L, 3000002209L, 
        3000002219L, 3000002227L, 3000002273L, 3000002279L, 3000002297L, 3000002333L, 
        3000002347L, 3000002351L, 3000002399L, 3000002417L, 3000002437L, 3000002491L, 
        3000002497L, 3000002501L, 3000002521L, 3000002561L};
    private static final List<BigInteger> BIGINT_PRIMES;

    static {
        BIGINT_PRIMES = new ArrayList<BigInteger>();
        for (long p: PRIMES)
            BIGINT_PRIMES.add(BigInteger.valueOf(p));
    }
    
    long[] coeffs;
    
    LongPolynomial(int N) {
        coeffs = new long[N];
    }

    LongPolynomial(long[] coeffs) {
        this.coeffs = coeffs;
    }

    LongPolynomial(IntegerPolynomial p) {
        coeffs = new long[p.coeffs.length];
        for (int i=0; i<coeffs.length; i++)
            coeffs[i] = p.coeffs[i];
    }
    
    /**
     * Resultant of this polynomial with x^n-1.
     * Returns (rho, res) satisfying res = rho*this + t*(x^n-1) for some integer t
     */
    Resultant resultant() {
        int N = coeffs.length;
        
        // upper bound for resultant(f, g) = ||f, 2||^deg(f) * ||g, 2||^deg(g) = squaresum(f)^(deg(f)/2) * 2^(N/2) because g(x)=x^N-1
        BigInteger max = squareSum().pow((degree()+1)/2);
        max = max.multiply(BigInteger.valueOf(2).pow((N+1)/2));
        BigInteger max2 = max.multiply(BigInteger.valueOf(2));
        BigInteger pProd = ONE;
        Iterator<BigInteger> primes = BIGINT_PRIMES.iterator();
        
        BigInteger res = ONE;
        BigIntPolynomial rhoP = new BigIntPolynomial(N);
        rhoP.coeffs[0] = ONE;
        BigInteger prime = BigInteger.valueOf(3000000000L);
        while (pProd.compareTo(max2) < 0) {
            if (primes.hasNext())
                prime = primes.next();
            else
                prime = prime.nextProbablePrime();
            Resultant crr = resultant(prime.longValue());
            
            BigInteger temp = pProd.multiply(prime);
            BigIntEuclidean er = BigIntEuclidean.calculate(prime, pProd);
            
            res = res.multiply(er.x.multiply(prime));
            BigInteger res2 = crr.res.multiply(er.y.multiply(pProd));
            res = res.add(res2).mod(temp);
            
            rhoP.mult(er.x.multiply(prime));
            BigIntPolynomial rho = crr.rho;
            rho.mult(er.y.multiply(pProd));
            rhoP.add(rho);
            rhoP.mod(temp);
            pProd = temp;
        }
        
        BigInteger pProd2 = pProd.divide(BigInteger.valueOf(2));
        BigInteger pProd2n = pProd2.negate();
        
        res = res.mod(pProd);
        if (res.compareTo(pProd2) > 0)
            res = res.subtract(pProd);
        if (res.compareTo(pProd2n) < 0)
            res = res.add(pProd);
        
        rhoP.mod(pProd);
        for (int i=0; i<N; i++) {
            BigInteger c = rhoP.coeffs[i];
            if (c.compareTo(pProd2) > 0)
                rhoP.coeffs[i] = c.subtract(pProd);
            if (c.compareTo(pProd2n) < 0)
                rhoP.coeffs[i] = c.add(pProd);
        }

        return new Resultant(rhoP, res);
    }
        
    /**
     * Resultant of this polynomial with x^n-1 mod p.
     * Returns (rho, res) satisfying res = rho*this + t*(x^n-1) mod p for some integer t.
     */
    Resultant resultant(long p) {
        // Add a coefficient as the following operations involve polynomials of degree deg(f)+1
        long[] fcoeffs = Arrays.copyOf(coeffs, coeffs.length+1);
        LongPolynomial f = new LongPolynomial(fcoeffs);
        int N = fcoeffs.length;
        
        LongPolynomial a = new LongPolynomial(N);
        a.coeffs[0] = -1;
        a.coeffs[N-1] = 1;
        LongPolynomial b = new LongPolynomial(f.coeffs);
        LongPolynomial v1 = new LongPolynomial(N);
        LongPolynomial v2 = new LongPolynomial(N);
        v2.coeffs[0] = 1;
        int da = N - 1;
        int db = b.degree();
        int ta = da;
        long c = 0;
        long r = 1;
        while (db > 0) {
            c = Util.invert(b.coeffs[db], p);
            c = (c * a.coeffs[da]) % p;
            a.multShiftSub(b, c, da-db, p);
            v1.multShiftSub(v2, c, da-db, p);
            
            da = a.degree();
            if (da < db) {
                r *= Util.pow(b.coeffs[db], ta-da, p);
                r %= p;
                if (ta%2==1 && db%2==1)
                    r = (-r) % p;
                LongPolynomial temp = a;
                a = b;
                b = temp;
                int tempdeg = da;
                da = db;
                temp = v1;
                v1 = v2;
                v2 = temp;
                ta = db;
                db = tempdeg;
            }
        }
        r *= Util.pow(b.coeffs[0], da, p);
        r %= p;
        c = Util.invert(b.coeffs[0], p);
        v2.mult(c);
        v2.mod(p);
        v2.mult(r);
        v2.mod(p);
        
        // drop the highest coefficient so #coeffs matches the original input
        v2.coeffs = Arrays.copyOf(v2.coeffs, v2.coeffs.length-1);
        return new Resultant(new BigIntPolynomial(v2), BigInteger.valueOf(r));
    }
    
    // this = this - b*c*(x^k) mod p
    private void multShiftSub(LongPolynomial b, long c, int k, long p) {
        int N = coeffs.length;
        for (int i=k; i<N; i++)
            coeffs[i] = (coeffs[i]-b.coeffs[i-k]*c) % p;
    }
    
    private BigInteger squareSum() {
        BigInteger sum = ZERO;
        for (int i=0; i<coeffs.length; i++)
            sum = sum.add(BigInteger.valueOf(coeffs[i]*coeffs[i]));
        return sum;
    }
    
    int degree() {
        int degree = coeffs.length - 1;
        while (degree>0 && coeffs[degree]==0)
            degree--;
        return degree;
    }
    
    /** Adds another polynomial which can have a different number of coefficients */
    void add(LongPolynomial b) {
        if (b.coeffs.length > coeffs.length)
            coeffs = Arrays.copyOf(coeffs, b.coeffs.length);
        for (int i=0; i<b.coeffs.length; i++)
            coeffs[i] += b.coeffs[i];
    }
    
    void mult(long factor) {
        for (int i=0; i<coeffs.length; i++)
            coeffs[i] *= factor;
    }
    
    void mod(long modulus) {
        for (int i=0; i<coeffs.length; i++)
            coeffs[i] %= modulus;
    }
}
