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

import static org.junit.Assert.assertArrayEquals;

import java.util.Random;

import org.junit.Test;

public class LongPolynomial2Test {
    
    @Test
    public void testMult() {
        IntegerPolynomial i1 = new IntegerPolynomial(new int[] {1368, 2047, 672, 871, 1662, 1352, 1099, 1608});
        IntegerPolynomial i2 = new IntegerPolynomial(new int[] {1729, 1924, 806, 179, 1530, 1381, 1695, 60});
        LongPolynomial2 a = new LongPolynomial2(i1);
        LongPolynomial2 b = new LongPolynomial2(i2);
        IntegerPolynomial c1 = i1.mult(i2, 2048);
        IntegerPolynomial c2 = a.mult(b).toIntegerPolynomial();
        assertArrayEquals(c1.coeffs, c2.coeffs);
        
        // test 10 random polynomials
        Random rng = new Random();
        for (int i=0; i<10; i++) {
            int N = 2 + rng.nextInt(2000);
            i1 = PolynomialGenerator.generateRandom(N, 2048);
            i2 = PolynomialGenerator.generateRandom(N, 2048);
            a = new LongPolynomial2(i1);
            b = new LongPolynomial2(i2);
            c1 = i1.mult(i2);
            c1.modPositive(2048);
            c2 = a.mult(b).toIntegerPolynomial();
            assertArrayEquals(c1.coeffs, c2.coeffs);
        }
    }
    
    @Test
    public void testSubAnd() {
        IntegerPolynomial i1 = new IntegerPolynomial(new int[] {1368, 2047, 672, 871, 1662, 1352, 1099, 1608});
        IntegerPolynomial i2 = new IntegerPolynomial(new int[] {1729, 1924, 806, 179, 1530, 1381, 1695, 60});
        LongPolynomial2 a = new LongPolynomial2(i1);
        LongPolynomial2 b = new LongPolynomial2(i2);
        a.subAnd(b, 2047);
        i1.sub(i2);
        i1.modPositive(2048);
        assertArrayEquals(a.toIntegerPolynomial().coeffs, i1.coeffs);
    }
    
    @Test
    public void testMult2And() {
        IntegerPolynomial i1 = new IntegerPolynomial(new int[] {1368, 2047, 672, 871, 1662, 1352, 1099, 1608});
        LongPolynomial2 i2 = new LongPolynomial2(i1);
        i2.mult2And(2047);
        i1.mult(2);
        i1.modPositive(2048);
        assertArrayEquals(i1.coeffs, i2.toIntegerPolynomial().coeffs);
    }
}