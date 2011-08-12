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

import static org.junit.Assert.assertEquals;

import java.math.BigInteger;

import net.sf.ntru.polynomial.BigIntPolynomial;
import net.sf.ntru.polynomial.DenseTernaryPolynomial;
import net.sf.ntru.polynomial.IntegerPolynomial;
import net.sf.ntru.polynomial.LongPolynomial;
import net.sf.ntru.sign.SignatureParameters;

import org.junit.Test;

public class LongPolynomialTest {
    
    @Test
    public void testResultant() {
        SignatureParameters params = SignatureParameters.APR2011_439;
        LongPolynomial a = new LongPolynomial(DenseTernaryPolynomial.generateRandom(params.N, params.d, params.d));
        verifyResultant(a, a.resultant());
        
        a = new LongPolynomial(new IntegerPolynomial(new int[] {0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 0, 0, 0, 0, 0, 1, -1, 0, 0, -1, 0, 0, 0, 1, 0, 0, 0, -1, -1, 0, -1, 1, -1, 0, -1, 0, -1, -1, -1, 0, 0, 0, 1, 1, -1, -1, -1, 0, -1, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, 1, 0, 0, 1, 1, -1, 0, 1, -1, 0, 1, 0, 1, 0, -1, -1, 0, 1, 0, -1, 1, 1, 1, 1, 0, 0, -1, -1, 1, 0, 0, -1, -1, 0, -1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, -1, 0, 0, 0, 0, -1, 0, 0, 0, 1, 0, 1, 0, 1, -1, 0, 0, 1, 1, 1, 0, 0, 0, -1, 0, 0, 0, 0, 1, 0, 1, 0, -1, -1, 0, -1, -1, -1, 0, -1, -1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, -1, 0, 1, 0, -1, 0, 0, 0, 0, 0, 0, -1, -1, 0, -1, -1, 1, 1, 0, 0, -1, 1, 0, 0, 0, -1, 1, -1, 0, -1, 0, 0, 0, -1, 0, 0, 0, 0, 0, -1, 1, 1, 0, 0, -1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, -1, 0, 1, 0, -1, -1, 0, 0, 0, 0, 0, 1, -1, 0, 0, 0, 1, -1, 1, -1, -1, 1, -1, 0, 1, 0, 0, 0, 1, 0, 0, 1, -1, 0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 0, -1, 0, 1, -1, 0, 0, 1, 1, 0, 0, 1, 1, 0, -1, 0, -1, 1, -1, -1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, -1, 0, 0, 1, -1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, -1, 1, 0, -1, -1, 0, 0, -1, 0, 1, 1, -1, 1, -1, 0, 0, 0, 1}));
        verifyResultant(a, a.resultant());
    }
    
    // verifies that res=rho*a mod x^n-1
    private void verifyResultant(LongPolynomial a, Resultant r) {
        BigIntPolynomial b = new BigIntPolynomial(a).mult(r.rho);
        
        for (int j=1; j<b.coeffs.length-1; j++)
            assertEquals(BigInteger.ZERO, b.coeffs[j]);
        if (r.res.equals(BigInteger.ZERO))
            assertEquals(BigInteger.ZERO, b.coeffs[0].subtract(b.coeffs[b.coeffs.length-1]));
        else
            assertEquals(BigInteger.ZERO, (b.coeffs[0].subtract(b.coeffs[b.coeffs.length-1]).mod(r.res)));
        assertEquals(b.coeffs[0].subtract(r.res), b.coeffs[b.coeffs.length-1].negate());
    }

    @Test
    public void testResultantMod() {
        int p = 46337;   // prime; must be less than sqrt(2^31) or integer overflows will occur
        
        LongPolynomial a = new LongPolynomial(new IntegerPolynomial(new int[] {0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 0, 0, 0, 0, 0, 1, -1, 0, 0, -1, 0, 0, 0, 1, 0, 0, 0, -1, -1, 0, -1, 1, -1, 0, -1, 0, -1, -1, -1, 0, 0, 0, 1, 1, -1, -1, -1, 0, -1, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, 1, 0, 0, 1, 1, -1, 0, 1, -1, 0, 1, 0, 1, 0, -1, -1, 0, 1, 0, -1, 1, 1, 1, 1, 0, 0, -1, -1, 1, 0, 0, -1, -1, 0, -1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, -1, 0, 0, 0, 0, -1, 0, 0, 0, 1, 0, 1, 0, 1, -1, 0, 0, 1, 1, 1, 0, 0, 0, -1, 0, 0, 0, 0, 1, 0, 1, 0, -1, -1, 0, -1, -1, -1, 0, -1, -1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, -1, 0, 1, 0, -1, 0, 0, 0, 0, 0, 0, -1, -1, 0, -1, -1, 1, 1, 0, 0, -1, 1, 0, 0, 0, -1, 1, -1, 0, -1, 0, 0, 0, -1, 0, 0, 0, 0, 0, -1, 1, 1, 0, 0, -1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, -1, 0, 1, 0, -1, -1, 0, 0, 0, 0, 0, 1, -1, 0, 0, 0, 1, -1, 1, -1, -1, 1, -1, 0, 1, 0, 0, 0, 1, 0, 0, 1, -1, 0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 0, -1, 0, 1, -1, 0, 0, 1, 1, 0, 0, 1, 1, 0, -1, 0, -1, 1, -1, -1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, -1, 0, 0, 1, -1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, -1, 1, 0, -1, -1, 0, 0, -1, 0, 1, 1, -1, 1, -1, 0, 0, 0, 1}));
        verifyResultant(a, a.resultant(p), p);
        
        for (int i=0; i<10; i++) {
            a = new LongPolynomial(DenseTernaryPolynomial.generateRandom(853));
            verifyResultant(a, a.resultant(p), p);
        }
    }
    
    // verifies that res=rho*a mod x^n-1 mod p
    private void verifyResultant(LongPolynomial a, Resultant r, int p) {
        BigIntPolynomial b = new BigIntPolynomial(a).mult(r.rho);
        b.mod(BigInteger.valueOf(p));
        
        for (int j=1; j<b.coeffs.length-1; j++)
            assertEquals(BigInteger.ZERO, b.coeffs[j]);
        if (r.res.equals(BigInteger.ZERO))
            assertEquals(BigInteger.ZERO, b.coeffs[0].subtract(b.coeffs[b.coeffs.length-1]));
        else
            assertEquals(BigInteger.ZERO, (b.coeffs[0].subtract(b.coeffs[b.coeffs.length-1]).subtract(r.res).mod(BigInteger.valueOf(p))));
        assertEquals(BigInteger.ZERO, b.coeffs[0].subtract(r.res).subtract(b.coeffs[b.coeffs.length-1].negate()).mod(BigInteger.valueOf(p)));
    }
}