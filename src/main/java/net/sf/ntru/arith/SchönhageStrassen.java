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

package net.sf.ntru.arith;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * An implementation of the
 * <a href="http://en.wikipedia.org/wiki/Sch%C3%B6nhage%E2%80%93Strassen_algorithm">Schönhage-Strassen algorithm</a>
 * for multiplying large numbers.
 * <p/>
 * References:
 * <ol>
 *   <li><a href="http://www.scribd.com/doc/68857222/Schnelle-Multiplikation-gro%C3%9Fer-Zahlen">
 *       Arnold Schönhage und Volker Strassen: Schnelle Multiplikation großer Zahlen, Computing 7, 1971, Springer-Verlag, S. 281–292</a></li>
 *   <li><a href="http://malte-leip.net/beschreibung_ssa.pdf">Eine verständliche Beschreibung des Schönhage-Strassen-Algorithmus</a></li>
 * </ol>
 * <p/>
 * Numbers are internally represented as <code>int</code> arrays; the <code>int</code>s are interpreted as unsigned numbers.
 */
public class SchönhageStrassen {
    private static final int KARATSUBA_THRESHOLD = 32;   // min #ints for Karatsuba
    
    /**
     * Multiplies two {@link BigInteger}s using Schönhage-Strassen if the numbers are above a certain size.
     * Otherwise, Karatsuba or O(n²) multiplication is used.
     * @param a
     * @param b
     * @return
     */
    public static BigInteger mult(BigInteger a, BigInteger b) {
        // remove any minus signs, multiply, then fix sign
        int signum = a.signum() * b.signum();
        if (a.signum() < 0)
            a = a.negate();
        if (b.signum() < 0)
            b = b.negate();
        
        byte[] aByteArr = reverse(a.toByteArray());
        int[] aIntArr = toIntArray(aByteArr);
        byte[] bByteArr = reverse(b.toByteArray());
        int[] bIntArr = toIntArray(bByteArr);
        
        int[] cIntArr = mult(aIntArr, a.bitLength(), bIntArr, b.bitLength());
        
        byte[] cByteArr = toByteArray(cIntArr);
        BigInteger c = new BigInteger(1, reverse(cByteArr));
        if (signum < 0)
            c = c.negate();
        
        return c;
    }
    
    /**
     * Multiplies two <b>positive</b> numbers represented as int arrays, i.e. in base <code>2^32</code>.
     * Positive means an int is always interpreted as an unsigned number, regardless of the sign bit.<br/>
     * The upper <code>a.length/2</code> and <code>b.length/2</code> digits must be zeros.<br/>
     * The arrays must be ordered least significant to most significant,
     * so the least significant digit must be at index 0.<br/>
     * @param a
     * @param b
     * @return
     */
    public static int[] mult(int[] a, int[] b) {
        return mult(a, a.length*32, b, b.length*32);
    }
    
    private static int[] mult(int[] a, int aBitLen, int[] b, int bBitLen) {
        if (!shouldUseSchönhageStrassen(Math.max(aBitLen, bBitLen)))
            return multKaratsuba(a, b);
        
        // set M to the number of binary digits in a or b, whichever is greater
        int M = Math.max(aBitLen, bBitLen);
        
        // find the lowest m such that m>log2(2M)
        int m = 32 - Integer.numberOfLeadingZeros(2*M);
        
        int n = m/2 + 1;
        
        // split a and b into pieces 1<<(n-1) bits long; assume n>=6 so pieces start and end at int boundaries
        boolean even = m%2 == 0;
        int numPieces = even ? 1<<n : 1<<(n+1);
        int pieceSize = 1 << (n-1-5);   // in ints
        int[][] ai = split(a, numPieces, pieceSize);
        int[][] bi = split(b, numPieces, pieceSize);
        
        // build u and v from ai and bi, allocating 3n+5 bits per element
        int[] u = new int[ai.length * (3*n+5) / 32];
        int uBitLength = 0;
        for (int i=0; i<ai.length; i++) {
            appendBits(u, uBitLength, ai[i], n+2);
            uBitLength += 3*n+5;
        }
        int[] v = new int[bi.length * (3*n+5) / 32];
        int vBitLength = 0;
        for (int i=0; i<bi.length; i++) {
            appendBits(v, vBitLength, bi[i], n+2);
            vBitLength += 3*n+5;
        }
        
        int[] gamma = mult(u, uBitLength, v, vBitLength);
        int[][] gammai = subdivide(gamma, 3*n+5);
        int halfNumPcs = numPieces / 2;
        
        int[][] zi = new int[gammai.length][];
        for (int i=0; i<gammai.length; i++)
            zi[i] = gammai[i];
        for (int i=0; i<gammai.length-halfNumPcs; i++)
            subModPow2(zi[i], gammai[i+halfNumPcs], n+2);
        for (int i=0; i<gammai.length-2*halfNumPcs; i++)
            addModPow2(zi[i], gammai[i+2*halfNumPcs], n+2);
        for (int i=0; i<gammai.length-3*halfNumPcs; i++)
            subModPow2(zi[i], gammai[i+3*halfNumPcs], n+2);
        
        // zr mod Fn
        int[][] aTrans = dft(ai, m, n);
        int[][] bTrans = dft(bi, m, n);
        modFn(aTrans);
        modFn(bTrans);
        int[][] cTrans = new int[aTrans.length][];
        for (int i=0; i<cTrans.length/2; i++)
            cTrans[i] = new int[0];
        for (int i=cTrans.length/2; i<cTrans.length; i++)
            cTrans[i] = multModFn(aTrans[i], bTrans[i]);
        int[][] c = idft(cTrans, m, n);
        modFn(c);

        int[] z = new int[1<<(m+1-5)];
        // calculate zr mod Fm from zr mod Fn and zr mod 2^(n+2), then add to z
        for (int i=0; i<numPieces/2; i++) {
            // zi = (zi-c[i]) % 2^(n+2)
            subModPow2(zi[i], c[i+numPieces/2], n+2);
            
            // zr = ci + delta*(2^2^n+1)
            int[] zr = Arrays.copyOf(zi[i], 3*(1<<(n-5)));
            addShifted(zr, zi[i], 1<<(n-5));
            add(zr, c[i+numPieces/2]);
            
            // z += zr * i * 2^(n-1)
            addShifted(z, zr, i*(1<<(n-1-5)));   // assume n>=6
        }
        
        modFn(z);   // assume m>=5
        return z;
    }
    
    /**
     * Estimates whether SS or Karatsuba will be more efficient when multiplying two numbers
     * of a given length in bits.
     * @param bitLength the number of bits in each of the two factors
     * @return <code>true</code> if SS is more efficient, <code>false</code> if Karatsuba is more efficient
     */
    private static boolean shouldUseSchönhageStrassen(int bitLength) {
        // The following values were determined experimentally on a 32-bit JVM.
        // Note that SS will fail for bit lengths below 2^16 because it goes into an endless recursion.
        if (bitLength>355000 && bitLength<524288)
            return true;
        if (bitLength > 552000)
            return true;
        return false;
    }
    
    /** Multiplies two <b>positive</b> numbers represented as <code>int</code> arrays. */
    static int[] multKaratsuba(int[] a, int[] b) {
        int n = Math.max(a.length, b.length);
        if (n <= KARATSUBA_THRESHOLD)
            return multSimple(a, b);
        else {
            int n1 = (n+1) / 2;
            
            int[] a1 = Arrays.copyOf(a, n1);
            int[] a2 = Arrays.copyOfRange(a, n1, n);
            int[] b1 = Arrays.copyOf(b, n1);
            int[] b2 = Arrays.copyOfRange(b, n1, n);
            
            int[] A = addExpand(a1, a2);
            int[] B = addExpand(b1, b2);
            
            int[] c1 = multKaratsuba(a1, b1);
            int[] c2 = multKaratsuba(a2, b2);
            int[] c3 = multKaratsuba(A, B);
            c3 = subExpand(c3, c1);   // c3-c1>0 because a and b are positive
            c3 = subExpand(c3, c2);   // c3-c2>0 because a and b are positive
            
            int[] c = Arrays.copyOf(c1, Math.max(n1+c3.length, 2*n1+c2.length));
            addShifted(c, c3, n1);
            addShifted(c, c2, 2*n1);
            
            return c;
        }
    }
    
    private static int[][] split(int[] a, int numPieces, int pieceSize) {
        int[][] ai = new int[numPieces][pieceSize];
        for (int i=0; i<a.length/pieceSize; i++)
            System.arraycopy(a, i*pieceSize, ai[i], 0, pieceSize);
        System.arraycopy(a, a.length/pieceSize*pieceSize, ai[a.length/pieceSize], 0, a.length%pieceSize);
        return ai;
    }
    
    private static int[] addExpand(int[] a, int[] b) {
        int[] c = Arrays.copyOf(a, Math.max(a.length, b.length));
        boolean carry = false;
        int i = 0;
        while (i < Math.min(b.length, a.length)) {
            int sum = a[i] + b[i];
            if (carry)
                sum++;
            carry = ((sum>>>31) < (a[i]>>>31)+(b[i]>>>31));   // carry if signBit(sum) < signBit(a)+signBit(b)
            c[i] = sum;
            i++;
        }
        while (carry) {
            if (i == c.length)
                c = Arrays.copyOf(c, c.length+1);
            c[i]++;
            carry = c[i] == 0;
            i++;
        }
        return c;
    }
    
    private static int[] subExpand(int[] a, int[] b) {
        int[] c = Arrays.copyOf(a, Math.max(a.length, b.length));
        boolean carry = false;
        int i = 0;
        while (i < Math.min(b.length, a.length)) {
            int diff = a[i] - b[i];
            if (carry)
                diff--;
            carry = ((diff>>>31) > (a[i]>>>31)-(b[i]>>>31));   // carry if signBit(diff) > signBit(a)-signBit(b)
            c[i] = diff;
            i++;
        }
        while (carry) {
            if (i == c.length)
                c = Arrays.copyOf(c, c.length+1);
            c[i]--;
            carry = c[i] == -1;
            i++;
        }
        return c;
    }
    
    /** O(n²) convolution */
    static int[] multSimple(int[] a, int[] b) {
        int[] c = new int[a.length+b.length];
        long carry = 0;
        for (int i=0; i<c.length; i++) {
            long ci = c[i] & 0xFFFFFFFFL;
            for (int k=Math.max(0,i-b.length+1); k<a.length&&k<=i; k++) {
                long prod = (a[k]&0xFFFFFFFFL) * (b[i-k]&0xFFFFFFFFL);
                ci += prod;
                carry += ci >>> 32;
                ci = ci << 32 >>> 32;
            }
            c[i] = (int)ci;
            if (i < c.length-1)
                c[i+1] = (int)carry;
            carry >>>= 32;
        }
        return c;
    }
    
    private static void add(int[] a, int[] b) {
        boolean carry = false;
        int i = 0;
        while (i < b.length) {
            int sum = a[i] + b[i];
            if (carry)
                sum++;
            carry = ((sum>>>31) < (a[i]>>>31)+(b[i]>>>31));   // carry if signBit(sum) < signBit(a)+signBit(b)
            a[i] = sum;
            i++;
        }
        while (carry) {
            a[i]++;
            carry = a[i] == 0;
            i++;
        }
    }
    
    /** drops elements of b that are shifted outside the valid range */
    static void addShifted(int[] a, int[] b, int numElements) {
        boolean carry = false;
        for (int i=0; i<Math.min(b.length, a.length-numElements); i++) {
            int ai = a[i+numElements];
            int sum = ai + b[i];
            if (carry)
                sum++;
            carry = ((sum>>>31) < (ai>>>31)+(b[i]>>>31));   // carry if signBit(sum) < signBit(a)+signBit(b)
            a[i+numElements] = sum;
        }
    }
    
    static void modFn(int[] a) {
        int len = a.length;
        boolean carry = false;
        for (int i=0; i<len/2; i++) {
            int bi = a[len/2+i];
            int diff = a[i] - bi;
            if (carry)
                diff--;
            carry = ((diff>>>31) > (a[i]>>>31)-(bi>>>31));   // carry if signBit(diff) > signBit(a)-signBit(b)
            a[i] = diff;
        }
        for (int i=len/2; i<len; i++)
            a[i] = 0;
        // if result is negative, add Fn; since Fn ≡ 1 (mod 2^n), it suffices to add 1
        if (carry) {
            int j = 0;
            do {
                int sum = a[j] + 1;
                a[j] = sum;
                carry = sum == 0;
                j++;
                if (j >= a.length)
                    j = 0;
            } while (carry);
        }
    }
    
    /**
     * Reduces all elements in the <b>upper half</b> of the outer array modulo <code>2^2^n+1</code>.
     * @param aTrans byte arrays of length <code>2^(n+1)</code> bits; n must be 6 or greater
     */
    static void modFn(int[][] a) {
        for (int i=a.length/2; i<a.length; i++)
            modFn(a[i]);
    }
    
    static int[][] dft(int[][] a, int m, int n) {
        boolean even = m%2 == 0;
        int len = a.length;
        int[][] A = extend(a, 1<<(n+1-5));
        int v = 0;
        int mask = len/2;   // masks the current bit
        
        int nmask = ~mask;   // the inverted bit mask
        for (int j=len/2; j<len; j+=len) {
            int idx = j;
            int x = getOmegaExponent(n, v, idx, even);
            
            for (int k=len/2-1; k>=0; k--) {
                int[] d = cyclicShiftLeftBits(A[idx|mask], x);
                // in the first slen loop, there are only subtractions
                int[] c = A[idx&nmask].clone();
                subModFn(c, d, 1<<n);
                A[idx] = c;
                idx++;
            }
        }
        v++;
        mask /= 2;
        
        for (int slen=len/4; slen>0; slen/=2) {   // slen = #consecutive coefficients for which the sign (add/sub) and x are constant
            nmask = ~mask;   // the inverted bit mask
            for (int j=len/2; j<len; j+=2*slen) {
                int idx = j;
                int x = getOmegaExponent(n, v, idx, even);
                
                for (int k=slen-1; k>=0; k--) {
                    int[] d = cyclicShiftLeftBits(A[idx|mask], x);
                    int[] c = A[idx&nmask];
                    A[idx] = c.clone();
                    addModFn(A[idx], d);
                    subModFn(c, d, 1<<n);
                    A[idx+slen] = c;
                    idx++;
                }
            }
            
            v++;
            mask /= 2;
        }
        return A;
    }
    
    private static int getOmegaExponent(int n, int v, int idx, boolean even) {
        int x;
        if (even) {
            x = Integer.reverse(idx >>> (n-v)) >>> (32-v);
            x <<= n - v - 1;
            // if m is odd, omega=2; if m is even, omega=4 which means double the shift amount
            x *= 2;
        }
        else {
            x = Integer.reverse(idx >>> (n+1-v)) >>> (32-v);
            x <<= n - v;
        }
        return x;
    }
    
    static int[][] idft(int[][] a, int m, int n) {
        boolean even = m%2 == 0;
        int len = a.length;
        int[][] A = extend(a, 1<<(n+1-5));
        int v = n - 1;
        int mask = 1;   // masks the current bit
        for (int slen=1; slen<=len/4; slen*=2) {   // slen = #consecutive coefficients for which the sign (add/sub) and x are constant
            int nmask = ~mask;   // the inverted bit mask
            for (int j=len/2; j<len; j+=2*slen) {
                int idx = j;
                int idx2 = idx + slen;   // idx2 is always idx+slen
                int x;
                if (even) {
                    x = Integer.reverse(idx >>> (n-v)) >>> (32-v);
                    x <<= n - v - 1;
                    // if m is odd, omega=2; if m is even, omega=4 which means double the shift amount
                    x *= 2;
                }
                else {
                    x = Integer.reverse(idx >>> (n-v)) >>> (32-v-1);
                    x <<= n - v - 1;
                    if (even)
                        x *= 2;   // if m is odd, omega=2; if m is even, omega=4 which means double the shift amount
                }
                x++;
                
                for (int k=slen-1; k>=0; k--) {
                    int[] c = A[idx&nmask].clone();
                    int[] d = A[idx|mask];
                    addModFn(A[idx], d);
                    A[idx] = cyclicShiftRight(A[idx], 1);
                    
                    subModFn(c, d, 1<<n);
                    A[idx2] = c;
                    A[idx2] = cyclicShiftRight(A[idx2], x);
                    idx++;
                    idx2++;
                }
            }
            
            v--;
            mask *= 2;
        }
        return A;
    }
    
    private static int[][] extend(int[][] a, int numElements) {
        int[][] b = new int[a.length][numElements];
        for (int i=0; i<a.length; i++)
            b[i] = Arrays.copyOf(a[i], numElements);
        return b;
    }
    
    static void addModFn(int[] a, int[] b) {
        boolean carry = false;
        for (int i=0; i<a.length; i++) {
            int sum = a[i] + b[i];
            if (carry)
                sum++;
            carry = ((sum>>>31) < (a[i]>>>31)+(b[i]>>>31));   // carry if signBit(sum) < signBit(a)+signBit(b)
            a[i] = sum;
        }
        
        // take a mod Fn by adding any remaining carry bit to the lowest bit;
        // since Fn ≡ 1 (mod 2^n), it suffices to add 1
        int i = 0;
        while (carry) {
            int sum = a[i] + 1;
            a[i] = sum;
            carry = sum == 0;
            i++;
            if (i >= a.length)
                i = 0;
        }
    }
    
    private static void subModFn(int[] a, int[] b, int pow2n) {
        addModFn(a, cyclicShiftLeftElements(b, pow2n/32));
    }
    
    private static void addModPow2(int[] a, int[] b, int numBits) {
        int numElements = (numBits+31) / 32;
        boolean carry = false;
        int i;
        for (i=0; i<numElements; i++) {
            int sum = a[i] + b[i];
            if (carry)
                sum++;
            carry = ((sum>>>31) < (a[i]>>>31)+(b[i]>>>31));   // carry if signBit(sum) < signBit(a)+signBit(b)
            a[i] = sum;
        }
        a[i-1] &= -1 >>> (32-(numBits%32));
        for (; i<a.length; i++)
            a[i] = 0;
    }
    
    static void subModPow2(int[] a, int[] b, int numBits) {
        int numElements = (numBits+31) / 32;
        boolean carry = false;
        int i;
        for (i=0; i<numElements; i++) {
            int diff = a[i] - b[i];
            if (carry)
                diff--;
            carry = ((diff>>>31) > (a[i]>>>31)-(b[i]>>>31));   // carry if signBit(diff) > signBit(a)-signBit(b)
            a[i] = diff;
        }
        a[i-1] &= -1 >>> (32-(numBits%32));
        for (; i<a.length; i++)
            a[i] = 0;
    }
    
    static int[] cyclicShiftRight(int[] a, int numBits) {
        int[] b = new int[a.length];
        int numElements = numBits / 32;
        System.arraycopy(a, numElements, b, 0, a.length-numElements);
        System.arraycopy(a, 0, b, a.length-numElements, numElements);
        
        numBits = numBits % 32;
        if (numBits != 0) {
            int b0 = b[0];
            b[0] = b[0] >>> numBits;
            for (int i=1; i<b.length; i++) {
                b[i-1] |= b[i] << (32-numBits);
                b[i] = b[i] >>> numBits;
            }
            b[b.length-1] |= b0 << (32-numBits);
        }
        return b;
    }
    
    /** a and b are assumed to be reduced mod Fn, i.e. 0<=a<Fn and 0<=b<Fn */
    static int[] multModFn(int[] a, int[] b) {
        int[] a0 = Arrays.copyOf(a, a.length/2);
        int[] b0 = Arrays.copyOf(b, b.length/2);
        int[] c = mult(a0, b0);
        int n = a.length/2;
        // special case: if a=Fn-1, add b*2^2^n which is the same as subtracting b
        if (a[n] == 1)
            subModFn(c, b0, 1<<n);
        if (b[n] == 1)
            subModFn(c, a0, 1<<n);
        return c;
    }
    
    /** left means towards the higher array indices and the higher bits */
    static int[] cyclicShiftLeftBits(int[] a, int numBits) {
        int[] b = cyclicShiftLeftElements(a, numBits/32);
        
        numBits = numBits % 32;
        if (numBits != 0) {
            int bhi = b[b.length-1];
            b[b.length-1] <<= numBits;
            for (int i=b.length-1; i>0; i--) {
                b[i] |= b[i-1] >>> (32-numBits);
                b[i-1] <<= numBits;
            }
            b[0] |= bhi >>> (32-numBits);
        }
        return b;
    }
    
    static int[] cyclicShiftLeftElements(int[] a, int numElements) {
        int[] b = new int[a.length];
        System.arraycopy(a, 0, b, numElements, a.length-numElements);
        System.arraycopy(a, a.length-numElements, b, 0, numElements);
        return b;
    }
    
    static void appendBits(int[] a, int aBitLength, int[] b, int bBitLength) {
        int aIdx = aBitLength / 32;
        int bit32 = aBitLength % 32;
        
        for (int i=0; i<bBitLength/32; i++) {
            if (bit32 > 0) {
                a[aIdx] |= b[i] << bit32;
                aIdx++;
                a[aIdx] = b[i] >>> (32-bit32);
            }
            else {
                a[aIdx] = b[i];
                aIdx++;
            }
        }
        
        if (bBitLength%32 > 0) {
            int bIdx = bBitLength / 32;
            int bi = b[bIdx];
            bi &= -1 >>> (32-bBitLength);
            a[aIdx] |= bi << bit32;
            if (bit32+(bBitLength%32) > 32)
                a[aIdx+1] = bi >>> (32-bit32);
        }
    }
    
    /** Divides a int array into pieces <code>bitLength</code> bits long */
    private static int[][] subdivide(int[] a, int bitLength) {
        int aIntIdx = 0;
        int aBitIdx = 0;
        int numPieces = (a.length*32+bitLength-1) / bitLength;
        int pieceLength = (bitLength+31) / 32;   // in ints
        int[][] b = new int[numPieces][pieceLength];
        for (int i=0; i<b.length; i++) {
            int bitsRemaining = Math.min(bitLength, a.length*32-i*bitLength);
            int bIntIdx = 0;
            int bBitIdx = 0;
            while (bitsRemaining > 0) {
                int bitsToCopy = Math.min(32-aBitIdx, 32-bBitIdx);
                bitsToCopy = Math.min(bitsRemaining, bitsToCopy);
                int mask = a[aIntIdx] >>> aBitIdx;
                mask &= -1 >>> (32-bitsToCopy);
                mask <<= bBitIdx;
                b[i][bIntIdx] |= mask;
                bitsRemaining -= bitsToCopy;
                aBitIdx += bitsToCopy;
                if (aBitIdx >= 32) {
                    aBitIdx -= 32;
                    aIntIdx++;
                }
                bBitIdx += bitsToCopy;
                if (bBitIdx >= 32) {
                    bBitIdx -= 32;
                    bIntIdx++;
                }
            }
        }
        return b;
    }
    
    public static int[] toIntArray(byte[] a) {
        int[] b = new int[(a.length+3)/4];
        for (int i=0; i<a.length; i++)
            b[i/4] += (a[i]&0xFF) << ((i%4)*8);
        return b;
    }
    
    public static byte[] toByteArray(int[] a) {
        byte[] b = new byte[a.length*4];
        for (int i=0; i<a.length; i++) {
            b[i*4] = (byte)(a[i] & 0xFF);
            b[i*4+1] = (byte)((a[i]>>>8) & 0xFF);
            b[i*4+2] = (byte)((a[i]>>>16) & 0xFF);
            b[i*4+3] = (byte)(a[i] >>> 24);
        }
        return b;
    }
    
    public static byte[] reverse(byte[] a) {
        byte[] b = new byte[a.length];
        for (int i=0; i<a.length; i++)
            b[i] = a[a.length-1-i];
        return b;
    }
}