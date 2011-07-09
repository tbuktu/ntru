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
    /** prime numbers &gt; <code>3*10^9</code> */
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
        3000002497L, 3000002501L, 3000002521L, 3000002561L, 3000002569L, 3000002591L, 
        3000002633L, 3000002639L, 3000002657L, 3000002669L, 3000002683L, 3000002693L, 
        3000002729L, 3000002741L, 3000002743L, 3000002779L, 3000002783L, 3000002813L, 
        3000002827L, 3000002849L, 3000002851L, 3000002867L, 3000002893L, 3000002981L, 
        3000002989L, 3000003007L, 3000003023L, 3000003037L, 3000003047L, 3000003067L, 
        3000003089L, 3000003113L, 3000003131L, 3000003133L, 3000003199L, 3000003217L, 
        3000003239L, 3000003247L, 3000003283L, 3000003287L, 3000003301L, 3000003313L, 
        3000003337L, 3000003341L, 3000003353L, 3000003371L, 3000003389L, 3000003437L, 
        3000003491L, 3000003493L, 3000003511L, 3000003521L, 3000003527L, 3000003529L, 
        3000003533L, 3000003557L, 3000003569L, 3000003599L, 3000003631L, 3000003649L, 
        3000003653L, 3000003667L, 3000003673L, 3000003733L, 3000003751L, 3000003757L, 
        3000003761L, 3000003817L, 3000003829L, 3000003871L, 3000003893L, 3000003913L, 
        3000003953L, 3000003959L, 3000003961L, 3000003971L, 3000004009L, 3000004019L, 
        3000004027L, 3000004037L, 3000004081L, 3000004087L, 3000004121L, 3000004171L, 
        3000004193L, 3000004201L, 3000004237L, 3000004243L, 3000004283L, 3000004291L, 
        3000004351L, 3000004367L, 3000004409L, 3000004451L, 3000004489L, 3000004523L, 
        3000004531L, 3000004537L, 3000004547L, 3000004549L, 3000004559L, 3000004573L, 
        3000004577L, 3000004589L, 3000004597L, 3000004619L, 3000004621L, 3000004627L, 
        3000004643L, 3000004649L, 3000004691L, 3000004699L, 3000004723L, 3000004769L, 
        3000004811L, 3000004849L, 3000004859L, 3000004901L, 3000004933L, 3000004939L, 
        3000004957L, 3000004993L, 3000004999L, 3000005017L, 3000005027L, 3000005053L, 
        3000005077L, 3000005083L, 3000005087L, 3000005093L, 3000005119L, 3000005131L, 
        3000005143L, 3000005149L, 3000005179L, 3000005189L, 3000005213L, 3000005227L, 
        3000005231L, 3000005243L};
    private static final List<BigInteger> BIGINT_PRIMES;

    static {
        BIGINT_PRIMES = new ArrayList<BigInteger>();
        for (long p: PRIMES)
            BIGINT_PRIMES.add(BigInteger.valueOf(p));
    }
    
    long[] coeffs;
    
    /**
     * Constructs a new polynomial with <code>N</code> coefficients initialized to 0.
     * @param N the number of coefficients
     */
    LongPolynomial(int N) {
        coeffs = new long[N];
    }

    /**
     * Constructs a new polynomial with a given set of coefficients.
     * @param coeffs the coefficients
     */
    LongPolynomial(long[] coeffs) {
        this.coeffs = coeffs;
    }

    /**
     * Constructs a <code>LongPolynomial</code> from a <code>IntegerPolynomial</code>. The two polynomials are independent of each other.
     * @param p the original polynomial
     */
    LongPolynomial(IntegerPolynomial p) {
        coeffs = new long[p.coeffs.length];
        for (int i=0; i<coeffs.length; i++)
            coeffs[i] = p.coeffs[i];
    }
    
    /**
     * Resultant of this polynomial with <code>x^n-1</code>.<br/>
     * @return <code>(rho, res)</code> satisfying <code>res = rho*this + t*(x^n-1)</code> for some integer <code>t</code>.
     */
    Resultant resultant() {
        int N = coeffs.length;
        
        // upper bound for resultant(f, g) = ||f, 2||^deg(f) * ||g, 2||^deg(g) = squaresum(f)^(deg(f)/2) * 2^(N/2) because g(x)=x^N-1
        // see http://jondalon.mathematik.uni-osnabrueck.de/staff/phpages/brunsw/CompAlg.pdf chapter 3
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
     * Resultant of this polynomial with <code>x^n-1 mod p</code>.<br/>
     * @return <code>(rho, res)</code> satisfying <code>res = rho*this + t*(x^n-1) mod p</code> for some integer <code>t</code>.
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
    
    /**
     * Computes <code>b*c*(x^k) mod p</code> and stores the result in this polynomial.
     * @param b
     * @param c
     * @param k
     * @param p
     */
    private void multShiftSub(LongPolynomial b, long c, int k, long p) {
        int N = coeffs.length;
        for (int i=k; i<N; i++)
            coeffs[i] = (coeffs[i]-b.coeffs[i-k]*c) % p;
    }
    
    /**
     * Adds the squares of all coefficients.
     * @return the sum of squares
     */
    private BigInteger squareSum() {
        BigInteger sum = ZERO;
        for (int i=0; i<coeffs.length; i++)
            sum = sum.add(BigInteger.valueOf(coeffs[i]*coeffs[i]));
        return sum;
    }
    
    /**
     * Returns the degree of the polynomial
     * @return the degree
     */
    int degree() {
        int degree = coeffs.length - 1;
        while (degree>0 && coeffs[degree]==0)
            degree--;
        return degree;
    }
    
    /**
     * Adds another polynomial which can have a different number of coefficients.
     * @param b another polynomial
     */
    void add(LongPolynomial b) {
        if (b.coeffs.length > coeffs.length)
            coeffs = Arrays.copyOf(coeffs, b.coeffs.length);
        for (int i=0; i<b.coeffs.length; i++)
            coeffs[i] += b.coeffs[i];
    }
    
    /**
     * Multiplies each coefficient by a <code>long</code>. Does not return a new polynomial but modifies this polynomial.
     * @param factor
     */
    void mult(long factor) {
        for (int i=0; i<coeffs.length; i++)
            coeffs[i] *= factor;
    }
    
    /**
     * Takes each coefficient modulo <code>modulus</code>.
     */
    void mod(long modulus) {
        for (int i=0; i<coeffs.length; i++)
            coeffs[i] %= modulus;
    }
}