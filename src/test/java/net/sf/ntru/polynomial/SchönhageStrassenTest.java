/**
 * Copyright (c) 2011 Tim Buktu (tbuktu@hotmail.com)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

package net.sf.ntru.polynomial;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

import org.junit.Test;

public class SchönhageStrassenTest {
    
    @Test
    public void testMult() {
        testMult(BigInteger.valueOf(0), BigInteger.valueOf(0));
        testMult(BigInteger.valueOf(100), BigInteger.valueOf(100));
        
        Random rng = new Random();
        testMult(BigInteger.valueOf(rng.nextInt(1000000000)+65536), BigInteger.valueOf(rng.nextInt(1000000000)+65536));
        testMult(BigInteger.valueOf((rng.nextLong()>>>1)+1000), BigInteger.valueOf((rng.nextLong()>>>1)+1000));
        
        for (int i=0; i<3; i++) {
            byte[] aArr = new byte[20000+rng.nextInt(50000)];
            rng.nextBytes(aArr);
            byte[] bArr = new byte[20000+rng.nextInt(50000)];
            rng.nextBytes(bArr);
            BigInteger a = new BigInteger(aArr);
            BigInteger b = new BigInteger(bArr);
            testMult(a, b);
        }
    }
    
    private void testMult(BigInteger a, BigInteger b) {
        assertEquals(a.multiply(b), SchönhageStrassen.mult(a, b));
    }
    
    @Test
    public void testModFn() {
        byte[][] a = new byte[][] {
                {0, 0},
                {0, 0},
                {0, 0},
                {0, 0},
                {0, 0},
                {0, 0},
                {0, 0},
                {0, 0},
                {84, 0},
                {62, 22},
                {103, 56},
                {6, -103},
                {-98, 7},
                {-118, 27},
                {-55, -127},
                {11, 64}
        };
        SchönhageStrassen.modFn(a);
        byte[][] aExpected = new byte[][] {
                {0, 0},
                {0, 0},
                {0, 0},
                {0, 0},
                {0, 0},
                {0, 0},
                {0, 0},
                {0, 0},
                {84, 0},
                {40, 0},
                {47, 0},
                {110, 0},
                {-105, 0},
                {111, 0},
                {72, 0},
                {-52, 0}
        };
        assertArrayEquals(aExpected, a);
    }
    
    @Test
    public void testDft() {
        int m = 5;
        int n = 3;
        
        byte[][] a = new byte[][] {
                {0, 6},
                {0, 3},
                {0, 14},
                {0, 2},
                {0, 0},
                {0, 0},
                {0, 0},
                {0, 0},
                {0, 0},
                {0, 0},
                {0, 0},
                {0, 0},
                {0, 0},
                {0, 0},
                {0, 0},
                {0, 0}
        };
        byte[][] aTrans = SchönhageStrassen.dft(a, m, n);
        byte[][] aExpected = new byte[][] {
                {0, 84},
                {22, 62},
                {56, 103},
                {-103, 6},
                {7, -98},
                {27, -118},
                {-127, -55},
                {64, 11}
        };
        assertArrayEquals(aExpected, Arrays.copyOfRange(aTrans, 8, 16));
        
        byte[][] b = new byte[][] {
                {0, 11},
                {0, 15},
                {0, 2},
                {0, 2},
                {0, 0},
                {0, 0},
                {0, 0},
                {0, 0},
                {0, 0},
                {0, 0},
                {0, 0},
                {0, 0},
                {0, 0},
                {0, 0},
                {0, 0},
                {0, 0}
        };
        byte[][] bTrans = SchönhageStrassen.dft(b, m, n);
        byte[][] bExpected = new byte[][] {
                {0, 65},
                {46, 19},
                {9, -20},
                {-23, 12},
                {5, 3},
                {120, -113},
                {-121, -53},
                {64, 19}
        };
        assertArrayEquals(bExpected, Arrays.copyOfRange(bTrans, 8, 16));
    }
    
    @Test
    public void testIdft() {
        int m = 5;
        int n = 3;
        byte[][] a = new byte[][] {
                {0, 0},
                {0, 0},
                {0, 0},
                {0, 0},
                {0, 0},
                {0, 0},
                {0, 0},
                {0, 0},
                {21, 84},
                {35, -16},
                {41, -83},
                {15, 120},
                {-106, 105},
                {9, -7},
                {19, 32},
                {-88, -16}
        };
        byte[][] aTrans = SchönhageStrassen.idft(a, m, n);
        byte[][] aExpected = new byte[][] {
                {-103, -37},
                {-3, 119},
                {122, 76},
                {-56, -63},
                {-117, -53},
                {-101, -69},
                {52, 56},
                {84, 84}
        };
        assertArrayEquals(aExpected, Arrays.copyOfRange(aTrans, 8, 16));
    }
    
    @Test
    public void testDftIdft() {
        for (int i=0; i<10; i++)
            testInversion();
    }
    
    /** verifies idft(idft(idft(...(dft(dft(dft(...(a))) = a */
    private void testInversion() {
        Random rng = new Random();
        
        int m = rng.nextInt(10) + 5;
        int n = m/2 + 1;
        int len = 1<<(n+1);
        byte[][] a = new byte[len][len/8];
        for (int i=0; i<a.length; i++)
            for (int j=0; j<a[0].length; j++)
                a[i][j] = (byte)rng.nextInt(256);
        byte[][] aTrans = a.clone();
        for (int i=0; i<10; i++)
            aTrans = SchönhageStrassen.dft(aTrans, m, n);
        for (int i=0; i<10; i++)
            aTrans = SchönhageStrassen.idft(aTrans, m, n);
        assertArrayEquals(Arrays.copyOf(a, a.length/2), Arrays.copyOf(aTrans, aTrans.length/2));
    }
    
    @Test
    public void testAddModFn() {
        Random rng = new Random();
        int n = 3 + rng.nextInt(10);
        int len = 1 << (n+1-3);
        byte[] aArr = new byte[len];
        rng.nextBytes(aArr);
        BigInteger a = new BigInteger(1, SchönhageStrassen.reverse(aArr));
        byte[] bArr = new byte[len];
        rng.nextBytes(bArr);
        BigInteger b = new BigInteger(1, SchönhageStrassen.reverse(bArr));
        SchönhageStrassen.addModFn(aArr, bArr);
        SchönhageStrassen.modFn(aArr);
        BigInteger Fn = BigInteger.valueOf(2).pow(1<<n).add(BigInteger.ONE);
        BigInteger c = a.add(b).mod(Fn);
        assertEquals(c, new BigInteger(1, SchönhageStrassen.reverse(aArr)));
    }
    
    @Test
    public void testMultModFn() {
        assertArrayEquals(new byte[] {100, 0, 15, -112}, SchönhageStrassen.multModFn(new byte[] {10, -64, 0, 0}, new byte[] {10, -64, 0, 0}));
    }
    
    @Test
    public void testSubModPow2() {
        byte[] a = new byte[] {4, 15, 0, 0, 0, 0, 0, 0, 0, 0};
        byte[] b = new byte[] {-5, 78, 98, 37, -44, 122, 22, 65, 28, 9};
        SchönhageStrassen.subModPow2(a, b, 12);
        assertArrayEquals(new byte[] {9, 0, 0, 0, 0, 0, 0, 0, 0, 0}, a);
    }
    
    @Test
    public void testCyclicShift() {
        byte[] arr = new byte[] {2, 3, -1, 127, -128};
        
        // test cyclicShiftLeft
        assertArrayEquals(new byte[] {5, 6, -2, -1, 0}, SchönhageStrassen.cyclicShiftLeft(arr, 1));
        assertArrayEquals(new byte[] {-128, 2, 3, -1, 127}, SchönhageStrassen.cyclicShiftLeft(arr, 8));
        assertArrayEquals(new byte[] {127, -128, 2, 3, -1}, SchönhageStrassen.cyclicShiftLeft(arr, 16));
        assertArrayEquals(new byte[] {-1, 127, -128, 2, 3}, SchönhageStrassen.cyclicShiftLeft(arr, 24));
        assertArrayEquals(new byte[] {3, -1, 127, -128, 2}, SchönhageStrassen.cyclicShiftLeft(arr, 32));
        assertArrayEquals(arr, SchönhageStrassen.cyclicShiftLeft(arr, 40));
        byte[] arr2 = SchönhageStrassen.cyclicShiftLeft(arr, 17);
        arr2 = SchönhageStrassen.cyclicShiftLeft(arr2, 12);
        arr2 = SchönhageStrassen.cyclicShiftLeft(arr2, 1);
        arr2 = SchönhageStrassen.cyclicShiftLeft(arr2, 1);
        arr2 = SchönhageStrassen.cyclicShiftLeft(arr2, 9);
        assertArrayEquals(arr, arr2);
        
        // test cyclicShiftRight
        assertArrayEquals(new byte[] {-127, -127, -1, 63, 64}, SchönhageStrassen.cyclicShiftRight(arr, 1));
        assertArrayEquals(new byte[] {3, -1, 127, -128, 2}, SchönhageStrassen.cyclicShiftRight(arr, 8));
        assertArrayEquals(new byte[] {-1, 127, -128, 2, 3}, SchönhageStrassen.cyclicShiftRight(arr, 16));
        assertArrayEquals(new byte[] {127, -128, 2, 3, -1}, SchönhageStrassen.cyclicShiftRight(arr, 24));
        assertArrayEquals(new byte[] {-128, 2, 3, -1, 127}, SchönhageStrassen.cyclicShiftRight(arr, 32));
        assertArrayEquals(new byte[] {2, 3, -1, 127, -128}, SchönhageStrassen.cyclicShiftRight(arr, 40));
        assertArrayEquals(arr, SchönhageStrassen.cyclicShiftRight(arr, 40));
        arr2 = SchönhageStrassen.cyclicShiftRight(arr, 17);
        arr2 = SchönhageStrassen.cyclicShiftRight(arr2, 12);
        arr2 = SchönhageStrassen.cyclicShiftRight(arr2, 1);
        arr2 = SchönhageStrassen.cyclicShiftRight(arr2, 1);
        arr2 = SchönhageStrassen.cyclicShiftRight(arr2, 9);
        assertArrayEquals(arr, arr2);
        
        // shift left, then right by the same amount
        arr2 = SchönhageStrassen.cyclicShiftLeft(arr, 22);
        arr2 = SchönhageStrassen.cyclicShiftRight(arr2, 22);
        assertArrayEquals(arr, arr2);
        arr2 = SchönhageStrassen.cyclicShiftLeft(arr, 9);
        arr2 = SchönhageStrassen.cyclicShiftRight(arr2, 14);
        arr2 = SchönhageStrassen.cyclicShiftRight(arr2, 9);
        arr2 = SchönhageStrassen.cyclicShiftLeft(arr2, 14);
        assertArrayEquals(arr, arr2);
    }
    
    @Test
    public void testAppendBits() {
        byte[] a = new byte[2];
        SchönhageStrassen.appendBits(a, 8, new byte[] {5}, 4);
        assertArrayEquals(new byte[] {0, 5}, a);
        
        a = new byte[] {33, 44, 55, 0, 0};
        SchönhageStrassen.appendBits(a, 22, new byte[] {101, -15}, 13);
        assertArrayEquals(new byte[] {33, 44, 119, 89, 60}, a);
    }
}