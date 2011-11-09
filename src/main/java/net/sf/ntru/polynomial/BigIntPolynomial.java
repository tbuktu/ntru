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

package net.sf.ntru.polynomial;

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

import net.sf.ntru.arith.SchönhageStrassen;
import net.sf.ntru.exception.NtruException;

/**
 * A polynomial with {@link BigInteger} coefficients.<br/>
 * Some methods (like <code>add</code>) change the polynomial, others (like <code>mult</code>) do
 * not but return the result as a new polynomial.
 */
public class BigIntPolynomial {
    private final static double LOG_10_2 = Math.log10(2);
    
    BigInteger[] coeffs;
    
    /**
     * Constructs a new polynomial with <code>N</code> coefficients initialized to 0.
     * @param N the number of coefficients
     */
    BigIntPolynomial(int N) {
        coeffs = new BigInteger[N];
        for (int i=0; i<N; i++)
            coeffs[i] = ZERO;
    }
    
    /**
     * Constructs a new polynomial with a given set of coefficients.
     * @param coeffs the coefficients
     */
    BigIntPolynomial(BigInteger[] coeffs) {
        this.coeffs = coeffs;
    }
    
    /**
     * Constructs a <code>BigIntPolynomial</code> from a <code>IntegerPolynomial</code>. The two polynomials are
     * independent of each other.
     * @param p the original polynomial
     */
    public BigIntPolynomial(IntegerPolynomial p) {
        coeffs = new BigInteger[p.coeffs.length];
        for (int i=0; i<coeffs.length; i++)
            coeffs[i] = BigInteger.valueOf(p.coeffs[i]);
    }
    
    /**
     * Generates a random polynomial with <code>numOnes</code> coefficients equal to 1,
     * <code>numNegOnes</code> coefficients equal to -1, and the rest equal to 0.
     * @param N number of coefficients
     * @param numOnes number of 1's
     * @param numNegOnes number of -1's
     * @return
     */
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
    
    /**
     * Multiplies the polynomial by another, taking the indices mod N. Does not
     * change this polynomial but returns the result as a new polynomial.<br/>
     * Both polynomials must have the same number of coefficients.
     * This method is designed for large polynomials and uses Schönhage-Strassen multiplication
     * in combination with
     * <a href="http://en.wikipedia.org/wiki/Kronecker_substitution">Kronecker substitution</a>.
     * See
     * <a href="http://math.stackexchange.com/questions/58946/karatsuba-vs-schonhage-strassen-for-multiplication-of-polynomials#58955">
     * here</a> for details.
     * @param poly2 the polynomial to multiply by
     * @return a new polynomial
     */
    public BigIntPolynomial multBig(BigIntPolynomial poly2) {
        int N = coeffs.length;
        
        // determine #bits needed per coefficient
        int logMinDigits = 32 - Integer.numberOfLeadingZeros(N-1);
        int maxLengthA = 0;
        for (BigInteger coeff: coeffs)
            maxLengthA = Math.max(maxLengthA, coeff.bitLength());
        int maxLengthB = 0;
        for (BigInteger coeff: poly2.coeffs)
            maxLengthB = Math.max(maxLengthB, coeff.bitLength());
        int k = logMinDigits + maxLengthA + maxLengthB + 1;   // in bits
        k = (k+31) / 32;   // in ints
        
        // encode each polynomial into an int[]
        int aDeg = degree();
        int bDeg = poly2.degree();
        if (aDeg<0 || bDeg<0)
            return new BigIntPolynomial(N);   // return zero
        int[] aInt = toIntArray(this, k);
        int[] bInt = toIntArray(poly2, k);
        
        int[] cInt = SchönhageStrassen.mult(aInt, bInt);
        
        // decode poly coefficients from the product
        BigInteger _2k = ONE.shiftLeft(k*32);
        BigIntPolynomial cPoly = new BigIntPolynomial(N);
        for (int i=0; i<2*N-1; i++) {
            int[] coeffInt = Arrays.copyOfRange(cInt, i*k, (i+1)*k);
            BigInteger coeff = new BigInteger(1, SchönhageStrassen.reverse(SchönhageStrassen.toByteArray(coeffInt)));
            if (coeffInt[k-1] < 0) {   // if coeff > 2^(k-1)
                coeff = coeff.subtract(_2k);
                
                // add 2^k to cInt which is the same as subtracting coeff
                boolean carry = false;
                int cIdx = (i+1) * k;
                do {
                    cInt[cIdx]++;
                    carry = cInt[cIdx] == 0;
                    cIdx++;
                } while (carry);
            }
            cPoly.coeffs[i%N] = cPoly.coeffs[i%N].add(coeff);
        }

        int aSign = coeffs[aDeg].signum();
        int bSign = poly2.coeffs[bDeg].signum();
        if (aSign*bSign < 0)
            for (int i=0; i<N; i++)
                cPoly.coeffs[i] = cPoly.coeffs[i].negate();
        
        return cPoly;
    }
    
    private int[] toIntArray(BigIntPolynomial a, int k) {
        int N = a.coeffs.length;
        
        int sign = a.coeffs[a.degree()].signum();
        
        int[] aInt = new int[N*k];
        for (int i=N-1; i>=0; i--) {
            int[] cArr = SchönhageStrassen.toIntArray(SchönhageStrassen.reverse(a.coeffs[i].abs().toByteArray()));
            if (a.coeffs[i].signum()*sign < 0)
                subShifted(aInt, cArr, i*k);
            else
                addShifted(aInt, cArr, i*k);
        }
        
        return aInt;
    }
    
    /** drops elements of b that are shifted outside the valid range */
    static void addShifted(int[] a, int[] b, int numElements) {
        boolean carry = false;
        int i = 0;
        while (i < Math.min(b.length, a.length-numElements)) {
            int ai = a[i+numElements];
            int sum = ai + b[i];
            if (carry)
                sum++;
            carry = ((sum>>>31) < (ai>>>31)+(b[i]>>>31));   // carry if signBit(sum) < signBit(a)+signBit(b)
            a[i+numElements] = sum;
            i++;
        }
        i += numElements;
        while (carry) {
            a[i]++;
            carry = a[i] == 0;
            i++;
        }
    }
    
    /** drops elements of b that are shifted outside the valid range */
    static void subShifted(int[] a, int[] b, int numElements) {
        boolean carry = false;
        int i = 0;
        while (i < Math.min(b.length, a.length-numElements)) {
            int ai = a[i+numElements];
            int diff = ai - b[i];
            if (carry)
                diff--;
            carry = ((diff>>>31) > (a[i]>>>31)-(b[i]>>>31));   // carry if signBit(diff) > signBit(a)-signBit(b)
            a[i+numElements] = diff;
            i++;
        }
        i += numElements;
        while (carry) {
            a[i]--;
            carry = a[i] == -1;
            i++;
        }
    }
    
    /**
     * Multiplies the polynomial by another, taking the indices mod N. Does not
     * change this polynomial but returns the result as a new polynomial.<br/>
     * Both polynomials must have the same number of coefficients.
     * This method is designed for smaller polynomials and uses 
     * <a href="http://en.wikipedia.org/wiki/Karatsuba_algorithm">Karatsuba multiplication</a>.
     * @param poly2 the polynomial to multiply by
     * @return a new polynomial
     * @throws NtruException if the two polynomials have a different number of coefficients
     */
    public BigIntPolynomial multSmall(BigIntPolynomial poly2) {
        int N = coeffs.length;
        if (poly2.coeffs.length != N)
            throw new NtruException("Number of coefficients must be the same");
        
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
    
    /**
     * Adds another polynomial which can have a different number of coefficients,
     * and takes the coefficient values mod <code>modulus</code>.
     * @param b another polynomial
     */
    void add(BigIntPolynomial b, BigInteger modulus) {
        add(b);
        mod(modulus);
    }
    
    /**
     * Adds another polynomial which can have a different number of coefficients.
     * @param b another polynomial
     */
    public void add(BigIntPolynomial b) {
      if (b.coeffs.length > coeffs.length) {
          int N = coeffs.length;
          coeffs = Arrays.copyOf(coeffs, b.coeffs.length);
          for (int i=N; i<coeffs.length; i++)
              coeffs[i] = ZERO;
      }
      for (int i=0; i<b.coeffs.length; i++)
          coeffs[i] = coeffs[i].add(b.coeffs[i]);
    }
    
    /**
     * Subtracts another polynomial which can have a different number of coefficients.
     * @param b another polynomial
     */
    public void sub(BigIntPolynomial b) {
        if (b.coeffs.length > coeffs.length) {
            int N = coeffs.length;
            coeffs = Arrays.copyOf(coeffs, b.coeffs.length);
            for (int i=N; i<coeffs.length; i++)
                coeffs[i] = ZERO;
        }
        for (int i=0; i<b.coeffs.length; i++)
            coeffs[i] = coeffs[i].subtract(b.coeffs[i]);
    }
    
    /**
     * Multiplies each coefficient by a <code>BigInteger</code>. Does not return a new polynomial but modifies this polynomial.
     * @param factor
     */
    public void mult(BigInteger factor) {
        for (int i=0; i<coeffs.length; i++)
            coeffs[i] = coeffs[i].multiply(factor);
    }
    
    /**
     * Multiplies each coefficient by a <code>int</code>. Does not return a new polynomial but modifies this polynomial.
     * @param factor
     */
    void mult(int factor) {
        mult(BigInteger.valueOf(factor));
    }
    
    /**
     * Divides each coefficient by a <code>BigInteger</code> and rounds the result to the nearest whole number.<br/>
     * Does not return a new polynomial but modifies this polynomial.
     * @param divisor the number to divide by
     */
    public void div(BigInteger divisor) {
        BigInteger d = divisor.add(ONE).divide(BigInteger.valueOf(2));
        for (int i=0; i<coeffs.length; i++) {
            coeffs[i] = coeffs[i].signum()>0 ? coeffs[i].add(d) : coeffs[i].add(d.negate());
            coeffs[i] = coeffs[i].divide(divisor);
        }
    }
    
    /**
     * Divides each coefficient by a <code>BigDecimal</code> and rounds the result to <code>decimalPlaces</code> places.
     * @param divisor the number to divide by
     * @param decimalPlaces the number of fractional digits to round the result to
     * @return a new <code>BigDecimalPolynomial</code>
     */
    public BigDecimalPolynomial div(BigDecimal divisor, int decimalPlaces) {
        BigInteger max = maxCoeffAbs();
        int coeffLength = (int)(max.bitLength() * LOG_10_2) + 1;
        // factor = 1/divisor
        BigDecimal factor = BigDecimal.ONE.divide(divisor, coeffLength+decimalPlaces+1, RoundingMode.HALF_EVEN);
        
        // multiply each coefficient by factor
        BigDecimalPolynomial p = new BigDecimalPolynomial(coeffs.length);
        for (int i=0; i<coeffs.length; i++)
            // multiply, then truncate after decimalPlaces so subsequent operations aren't slowed down
            p.coeffs[i] = new BigDecimal(coeffs[i]).multiply(factor).setScale(decimalPlaces, RoundingMode.HALF_EVEN);
        
        return p;
    }
    
    /**
     * Returns the base10 length of the largest coefficient.
     * @return length of the longest coefficient
     */
    public int getMaxCoeffLength() {
        return (int)(maxCoeffAbs().bitLength() * LOG_10_2) + 1;
    }
    
    private BigInteger maxCoeffAbs() {
        BigInteger max = coeffs[0].abs();
        for (int i=1; i<coeffs.length; i++) {
            BigInteger coeff = coeffs[i].abs();
            if (coeff.compareTo(max) > 0)
                max = coeff;
        }
        return max;
    }
    
    /**
     * Takes each coefficient modulo a number.
     * @param modulus
     */
    void mod(BigInteger modulus) {
        for (int i=0; i<coeffs.length; i++)
            coeffs[i] = coeffs[i].mod(modulus);
    }
    
    /** Returns the degree of the polynomial or -1 if the degree is negative */
    private int degree() {
        int degree = coeffs.length - 1;
        while (degree>=0 && coeffs[degree].equals(ZERO))
            degree--;
        return degree;
    }
    
    /**
     * Makes a copy of the polynomial that is independent of the original.
     */
    @Override
    public BigIntPolynomial clone() {
        return new BigIntPolynomial(coeffs.clone());
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + Arrays.hashCode(coeffs);
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        BigIntPolynomial other = (BigIntPolynomial) obj;
        if (!Arrays.equals(coeffs, other.coeffs))
            return false;
        return true;
    }
}