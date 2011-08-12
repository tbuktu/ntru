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

package net.sf.ntru.util;

import static org.junit.Assert.assertArrayEquals;

import java.util.Random;

import net.sf.ntru.polynomial.DenseTernaryPolynomial;
import net.sf.ntru.polynomial.PolynomialGenerator;
import net.sf.ntru.util.ArrayEncoder;

import org.junit.Test;

public class ArrayEncoderTest {
    
    @Test
    public void testEncodeDecodeModQ() {
        int[] coeffs = PolynomialGenerator.generateRandom(1000, 2048).coeffs;
        byte[] data = ArrayEncoder.encodeModQ(coeffs, 2048);
        int[] coeffs2 = ArrayEncoder.decodeModQ(data, 1000, 2048);
        assertArrayEquals(coeffs, coeffs2);
    }
    
    @Test
    public void testEncodeDecodeMod3() {
        Random rng = new Random();
        byte[] data = new byte[180];
        rng.nextBytes(data);
        int[] coeffs = ArrayEncoder.decodeMod3(data, 960);
        byte[] data2 = ArrayEncoder.encodeMod3(coeffs);
        assertArrayEquals(data, data2);
    }
    
    @Test
    public void testEncodeDecodeMod3Arith() {
        int[] coeffs = DenseTernaryPolynomial.generateRandom(1000).coeffs;
        byte[] data = ArrayEncoder.encodeMod3Arith(coeffs);
        int[] coeffs2 = ArrayEncoder.decodeMod3Arith(data, 1000);
        assertArrayEquals(coeffs, coeffs2);
    }
}