package net.sf.ntru;

import static org.junit.Assert.assertArrayEquals;

import org.junit.Test;

public class BigIntPolynomialTest {
    
    @Test
    public void testMult() {
        BigIntPolynomial a = new BigIntPolynomial(new IntegerPolynomial(new int[] {4, -1, 9, 2, 1, -5, 12, -7, 0, -9, 5}));
        BigIntPolynomial b = new BigIntPolynomial(new IntegerPolynomial(new int[] {-6, 0, 0, 13, 3, -2, -4, 10, 11, 2, -1}));
        BigIntPolynomial c = a.mult(b);
        assertArrayEquals(c.coeffs, new BigIntPolynomial(new IntegerPolynomial(new int[] {2, -189, 77, 124, -29, 0, -75, 124, -49, 267, 34})).coeffs);
    }
}