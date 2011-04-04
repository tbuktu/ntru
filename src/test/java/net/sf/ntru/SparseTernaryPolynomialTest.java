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

import static org.junit.Assert.*;

import org.junit.Test;

public class SparseTernaryPolynomialTest {
    
    @Test
    public void testMult() {
        IntegerPolynomial p1Int = IntegerPolynomial.generateRandomSmall(1000, 500, 500);
        SparseTernaryPolynomial p1 = new SparseTernaryPolynomial(p1Int);
        IntegerPolynomial p2 = IntegerPolynomial.generateRandom(1000);
        
        IntegerPolynomial prod1 = p1Int.mult(p2);
        prod1 = p1Int.mult(p2);
        IntegerPolynomial prod2 = p1.mult(p2);
        assertArrayEquals(prod1.coeffs, prod2.coeffs);
    }
}