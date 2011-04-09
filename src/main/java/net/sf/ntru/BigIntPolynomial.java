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
import java.math.RoundingMode;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

class BigIntPolynomial {
    BigInteger[] coeffs;
    
    BigIntPolynomial(int N) {
        coeffs = new BigInteger[N];
        for (int i=0; i<N; i++)
            coeffs[i] = ZERO;
    }
    
    BigIntPolynomial(IntegerPolynomial p) {
        coeffs = new BigInteger[p.coeffs.length];
        for (int i=0; i<coeffs.length; i++)
            coeffs[i] = BigInteger.valueOf(p.coeffs[i]);
    }
    
    BigIntPolynomial(BigInteger[] coeffs) {
        this.coeffs = coeffs;
    }
    
    // Generates a random polynomial with numOnes coefficients equal to 1,
    // numNegOnes coefficients equal to -1, and the rest equal to 0.
    static BigIntPolynomial generateRandomSmall(int N, int numOnes, int numNegOnes) {
        List<BigInteger> coeffs = new ArrayList<BigInteger>();
        for (int i=0; i<numOnes; i++)
            coeffs.add(ONE);
        for (int i=0; i<numNegOnes; i++)
            coeffs.add(BigInteger.valueOf(-1));
        while (coeffs.size() < N)
            coeffs.add(ZERO);
        Collections.shuffle(coeffs, new SecureRandom());
        
        BigIntPolynomial poly = new BigIntPolynomial(N);
        for (int i=0; i<coeffs.size(); i++)
            poly.coeffs[i] = coeffs.get(i);
        return poly;
    }
    
    BigIntPolynomial mult(BigIntPolynomial poly2, BigInteger modulus) {
        BigIntPolynomial c = mult(poly2);
        c.mod(modulus);
        return c;
    }
    
    BigIntPolynomial mult(IntegerPolynomial poly2) {
        return mult(new BigIntPolynomial(poly2));
    }
    
    /** Multiplies the polynomial with another, taking the indices mod N */
    BigIntPolynomial mult(BigIntPolynomial poly2) {
        int N = coeffs.length;
        if (poly2.coeffs.length != N)
            throw new RuntimeException("Number of coefficients must be the same");
        
        BigIntPolynomial c = multRecursive(poly2);
        
        if (c.coeffs.length > N) {
            for (int k=N; k<c.coeffs.length; k++)
                c.coeffs[k-N] = c.coeffs[k-N].add(c.coeffs[k]);
            c.coeffs = Arrays.copyOf(c.coeffs, N);
        }
        return c;
    }
    
    /** Karazuba multiplication */
    private BigIntPolynomial multRecursive(BigIntPolynomial poly2) {
        BigInteger[] a = coeffs;
        BigInteger[] b = poly2.coeffs;
        
        int n = poly2.coeffs.length;
        if (n <= 1) {
            BigInteger[] c = coeffs.clone();
            for (int i=0; i<coeffs.length; i++)
                c[i] = c[i].multiply(poly2.coeffs[0]);
            return new BigIntPolynomial(c);
        }
        else {
            int n1 = n / 2;
            
            BigIntPolynomial a1 = new BigIntPolynomial(Arrays.copyOf(a, n1));
            BigIntPolynomial a2 = new BigIntPolynomial(Arrays.copyOfRange(a, n1, n));
            BigIntPolynomial b1 = new BigIntPolynomial(Arrays.copyOf(b, n1));
            BigIntPolynomial b2 = new BigIntPolynomial(Arrays.copyOfRange(b, n1, n));
            
            BigIntPolynomial A = a1.clone();
            A.add(a2);
            BigIntPolynomial B = b1.clone();
            B.add(b2);
            
            BigIntPolynomial c1 = a1.multRecursive(b1);
            BigIntPolynomial c2 = a2.multRecursive(b2);
            BigIntPolynomial c3 = A.multRecursive(B);
            c3.sub(c1);
            c3.sub(c2);
            
            BigIntPolynomial c = new BigIntPolynomial(2*n-1);
            for (int i=0; i<c1.coeffs.length; i++)
                c.coeffs[i] = c1.coeffs[i];
            for (int i=0; i<c3.coeffs.length; i++)
                c.coeffs[n1+i] = c.coeffs[n1+i].add(c3.coeffs[i]);
            for (int i=0; i<c2.coeffs.length; i++)
                c.coeffs[2*n1+i] = c.coeffs[2*n1+i].add(c2.coeffs[i]);
            return c;
        }
    }
    
    void add(BigIntPolynomial b, BigInteger modulus) {
        add(b);
        mod(modulus);
    }
    
    /** Adds another polynomial which can have a different number of coefficients */
    void add(BigIntPolynomial b) {
      if (b.coeffs.length > coeffs.length) {
          int N = coeffs.length;
          coeffs = Arrays.copyOf(coeffs, b.coeffs.length);
          for (int i=N; i<coeffs.length; i++)
              coeffs[i] = ZERO;
      }
      for (int i=0; i<b.coeffs.length; i++)
          coeffs[i] = coeffs[i].add(b.coeffs[i]);
    }
    
    /** Subtracts another polynomial which can have a different number of coefficients */
    void sub(BigIntPolynomial b) {
        if (b.coeffs.length > coeffs.length) {
            int N = coeffs.length;
            coeffs = Arrays.copyOf(coeffs, b.coeffs.length);
            for (int i=N; i<coeffs.length; i++)
                coeffs[i] = ZERO;
        }
        for (int i=0; i<b.coeffs.length; i++)
            coeffs[i] = coeffs[i].subtract(b.coeffs[i]);
    }
    
    void mult(BigInteger factor) {
        for (int i=0; i<coeffs.length; i++)
            coeffs[i] = coeffs[i].multiply(factor);
    }
    
    void mult(int factor) {
        mult(BigInteger.valueOf(factor));
    }
    
    /** integer division */
    void div(BigInteger divisor) {
        BigInteger d = divisor.add(ONE).divide(BigInteger.valueOf(2));
        for (int i=0; i<coeffs.length; i++) {
            coeffs[i] = coeffs[i].compareTo(ZERO)>0 ? coeffs[i].add(d) : coeffs[i].add(d.negate());
            coeffs[i] = coeffs[i].divide(divisor);
        }
    }
    
    /** fractional division */
    BigDecimalPolynomial div(BigDecimal divisor, int decimalPlaces) {
        BigDecimalPolynomial p = new BigDecimalPolynomial(coeffs.length);
        for (int i=0; i<coeffs.length; i++)
            p.coeffs[i] = new BigDecimal(coeffs[i]).divide(divisor, decimalPlaces, RoundingMode.HALF_EVEN);
        return p;
    }
    
    void mod(BigInteger modulus) {
        for (int i=0; i<coeffs.length; i++)
            coeffs[i] = coeffs[i].mod(modulus);
    }
    
    BigInteger sumCoeffs() {
        BigInteger sum = ZERO;
        for (int i=0; i<coeffs.length; i++)
            sum = sum.add(coeffs[i]);
        return sum;
    }
    
    void clear() {
        for (int i=0; i<coeffs.length; i++)
            coeffs[i] = ZERO;
    }
    
    @Override
    public BigIntPolynomial clone() {
        return new BigIntPolynomial(coeffs.clone());
    }
}