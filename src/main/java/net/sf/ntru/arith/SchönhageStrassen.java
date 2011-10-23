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
 * TODO: use int[] instead of byte[]
 * TODO: use Karatsuba instead of BigInteger.multiply()
 */
public class SchönhageStrassen {
    private static final int BIT_LENGTH_THRESHOLD = 100000;   // must be at least 2^16 for the recursion to terminate
    
    /**
     * Multiplies two {@link BigInteger}s using Schönhage-Strassen if the numbers are above a certain size.
     * @param a
     * @param b
     * @return
     */
    public static BigInteger mult(BigInteger a, BigInteger b) {
        if (Math.min(a.bitLength(), b.bitLength()) < BIT_LENGTH_THRESHOLD)
            return a.multiply(b);
        
        // remove any minus signs, multiply, then fix sign
        int signum = a.signum() * b.signum();
        if (a.signum() < 0)
            a = a.negate();
        if (b.signum() < 0)
            b = b.negate();
        
        byte[] aArr = reverse(a.toByteArray());
        byte[] bArr = reverse(b.toByteArray());
        byte[] cArr = mult(aArr, a.bitLength(), bArr, b.bitLength());
        BigInteger c = new BigInteger(reverse(cArr));
        if (signum < 0)
            c = c.negate();
        return c;
    }
    
    /**
     * Multiplies two <b>positive</b> numbers represented as byte arrays, i.e. in base 256.<br/>
     * The upper <code>a.length/2</code> and <code>b.length/2</code> digits must be zeros.<br/>
     * The arrays must be ordered least significant to most significant,
     * so the least significant digit must be at index 0.<br/>
     * Note that this format is not compatible to {@link BigInteger#toByteArray()}.
     * @param a
     * @param aBitLen
     * @param b
     * @param bBitLen
     * @return
     */
    private static byte[] mult(byte[] a, int aBitLen, byte[] b, int bBitLen) {
        if (Math.min(aBitLen, bBitLen) < BIT_LENGTH_THRESHOLD) {
            byte[] c = reverse(new BigInteger(reverse(a)).multiply(new BigInteger(reverse(b))).toByteArray());
            // if the sign bit appended by toByteArray() increases the array length, trim the array
            if (c.length > Math.max(a.length, b.length))
                c = Arrays.copyOf(c, Math.max(a.length, b.length));
            return c;
        }
        
        // set M to the number of binary digits in a or b, whichever is greater
        int M = Math.max(aBitLen, bBitLen);
        
        // find the lowest m such that m>log2(2M)
        int m = 32 - Integer.numberOfLeadingZeros(2*M);
        
        int n = m/2 + 1;
        
        // split a and b into pieces 1<<(n-1) bits long; assume n>=4 so pieces start and end at byte boundaries
        boolean even = m%2 == 0;
        int numPieces = even ? 1<<n : 1<<(n+1);
        int pieceSize = 1 << (n-1-3);   // in bytes
        int totalBits = even ? 1<<(2*n-1) : 1<<(2*n);   // numPieces * pieceSize
        byte[][] ai = new byte[numPieces][pieceSize];
        a = Arrays.copyOf(a, totalBits/8);
        for (int i=0; i<numPieces; i++)
            System.arraycopy(a, i*pieceSize, ai[i], 0, pieceSize);
        
        byte[][] bi = new byte[numPieces][pieceSize];
        b = Arrays.copyOf(b, totalBits/8);
        for (int i=0; i<numPieces; i++)
            System.arraycopy(b, i*pieceSize, bi[i], 0, pieceSize);
        
        // alpha[i] = ai[i] modulo 2^(n+2), beta[i] = bi[i] modulo 2^(n+2)
        byte[][] alpha = new byte[numPieces][(n+2+7)/8];
        byte[][] beta = new byte[numPieces][(n+2+7)/8];
        int fullBytes = (n+2) / 8;
        int extraBits = (n+2) % 8;
        int mask = 0xFF >>> (8-extraBits);   // masks the low extraBits
        for (int i=0; i<numPieces; i++) {
            for (int j=0; j<fullBytes; j++) {
                alpha[i][j] = ai[i][j];
                beta[i][j] = bi[i][j];
            }
            alpha[i][fullBytes] = (byte)(ai[i][fullBytes] & mask);
            beta[i][fullBytes] = (byte)(bi[i][fullBytes] & mask);
        }
        
        // build u and v from alpha and beta, allocating 3n+5 bits per element
        int uvLen = numPieces * (3*n+5);   // #bits
        uvLen = (uvLen+7) / 8;   // #bytes
        byte[] u = new byte[uvLen];
        byte[] v = new byte[uvLen];
        int uBitLength = 0;
        int vBitLength = 0;
        for (int i=0; i<numPieces; i++) {
            appendBits(u, uBitLength, alpha[i], n+2);
            uBitLength += 3*n+5;
            appendBits(v, vBitLength, beta[i], n+2);
            vBitLength += 3*n+5;
        }
        
        byte[] gamma = mult(u, uBitLength, v, vBitLength);
        byte[][] gammai = subdivide(gamma, 3*n+5);
        int halfNumPcs = numPieces / 2;
        gammai = Arrays.copyOf(gammai, 4*halfNumPcs);
        for (int i=0; i<gammai.length; i++)
            if (gammai[i] == null)
                gammai[i] = new byte[(3*n+5+7)/8];
        
        byte[][] zi = new byte[halfNumPcs][(3*n+5+7)/8];
        for (int i=0; i<halfNumPcs; i++) {
            zi[i] = gammai[i].clone();
            addModPow2(zi[i], gammai[i+2*halfNumPcs], n+2);
            subModPow2(zi[i], gammai[i+halfNumPcs], n+2);
            subModPow2(zi[i], gammai[i+3*halfNumPcs], n+2);
        }
        
        // zr mod Fn
        ai = extend(ai, 1<<(n+1-3));
        bi = extend(bi, 1<<(n+1-3));
        byte[][] aTrans = dft(ai, m, n);
        byte[][] bTrans = dft(bi, m, n);
        modFn(aTrans);
        modFn(bTrans);
        byte[][] cTrans = new byte[aTrans.length][aTrans[0].length];
        for (int i=cTrans.length/2; i<cTrans.length; i++)
            cTrans[i] = multModFn(aTrans[i], bTrans[i]);
        byte[][] c = idft(cTrans, m, n);
        modFn(c);

        byte[] z = new byte[1<<(m+1-3)];
        // calculate zr mod Fm from zr mod Fn and zr mod 2^(n+2), then add to z
        for (int i=0; i<numPieces/2; i++) {
            // zi = (zi-c[i]) % 2^(n+2)
            subModPow2(zi[i], c[i+numPieces/2], n+2);
            
            // zr = zi + delta*(2^2^n+1)
            byte[] zr = Arrays.copyOf(zi[i], 3*(1<<(n-3)));
            byte[] delta = zr.clone();
            shiftLeft(delta, 1<<n);
            add(zr, delta);
            add(zr, c[i+numPieces/2]);
            
            // z += zr * i * 2^(n-1)
            addShifted(z, zr, i*(1<<(n-1-3)));   // assume n>=4
        }
        
        modFn(z);   // assume m>=3
        return z;
    }
    
    private static void add(byte[] a, byte[] b) {
        boolean carry = false;
        for (int i=0; i<b.length; i++) {
            int sum = (a[i]&0xFF) + (b[i]&0xFF);
            if (carry)
                sum++;
            a[i] = (byte)sum;
            carry = sum >= 256;
        }
    }
    
    /** drops elements of b that are shifted outside the valid range */
    private static void addShifted(byte[] a, byte[] b, int numBytes) {
        boolean carry = false;
        for (int i=0; i<Math.min(b.length, a.length-numBytes); i++) {
            int sum = (a[i+numBytes]&0xFF) + (b[i]&0xFF);
            if (carry)
                sum++;
            a[i+numBytes] = (byte)sum;
            carry = sum >= 256;
        }
    }
    
    static void modFn(byte[] a) {
        int len = a.length;
        boolean carry = false;
        for (int j=0; j<len/2; j++) {
            int diff = (a[j]&0xFF) - (a[len/2+j]&0xFF);
            if (carry)
                diff--;
            a[j] = (byte)diff;
            carry = diff < 0;
        }
        for (int j=len/2; j<len; j++)
            a[j] = 0;
        // if result is negative, add Fn (mod 2^n)
        if (carry) {
            int j = 0;
            do {
                int sum = (a[j]&0xFF) + 1;
                a[j] = (byte)sum;
                carry = sum >= 256;
                j++;
                if (j >= a.length)
                    j = 0;
            } while (carry);
        }
    }
    
    /**
     * Reduces all elements in the <b>upper half</b> of the outer array modulo <code>2^2^n+1</code>.
     * @param aTrans byte arrays of length <code>2^(n+1)</code> bits; n must be 4 or greater
     */
    static void modFn(byte[][] a) {
        for (int i=a.length/2; i<a.length; i++) {
            int len = a[i].length;
            boolean carry = false;
            for (int j=0; j<len/2; j++) {
                int diff = (a[i][j]&0xFF) - (a[i][len/2+j]&0xFF);
                if (carry)
                    diff--;
                a[i][j] = (byte)diff;
                carry = diff < 0;
            }
            for (int j=len/2; j<len; j++)
                a[i][j] = 0;
            // if result is negative, add Fn
            if (carry) {
                int j = 0;
                do {
                    int sum = (a[i][j]&0xFF) + 1;
                    a[i][j] = (byte)sum;
                    carry = sum >= 256;
                    j++;
                    if (j >= a.length)
                        j = 0;
                } while (carry);
            }
        }
    }
    
    static byte[][] dft(byte[][] a, int m, int n) {
        boolean even = m%2 == 0;
        int len = a.length;
        byte[][] A = extend(a, 1<<(n+1-3));
        int v = 0;
        int mask = len/2;   // masks the current bit
        for (int slen=len/2; slen>=1; slen/=2) {   // slen = #consecutive coefficients for which the sign (add/sub) and x are constant
            int nmask = ~mask;   // the inverted bit mask
            for (int j=len/2; j<len; j+=2*slen) {
                int idx = j;
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
                
                for (int k=0; k<slen; k++) {
                    byte[] c = A[idx&nmask].clone();
                    byte[] d = cyclicShiftLeft(A[idx|mask], x);
                    if (slen < len/2) {
                        A[idx] = c.clone();
                        addModFn(A[idx], d);
                        subModFn(c, d, 1<<n);
                        A[idx+slen] = c;
                    }
                    else {   // in the first slen loop, there are only subtractions
                        subModFn(c, d, 1<<n);
                        A[idx] = c;
                    }
                    idx++;
                }
            }
            
            v++;
            mask /= 2;
        }
        return A;
    }
    
    static byte[][] idft(byte[][] a, int m, int n) {
        boolean even = m%2 == 0;
        int len = a.length;
        byte[][] A = extend(a, 1<<(n+1-3));
        int v = n - 1;
        int mask = 1;   // masks the current bit
        for (int slen=1; slen<=len/4; slen*=2) {   // slen = #consecutive coefficients for which the sign (add/sub) and x are constant
            int nmask = ~mask;   // the inverted bit mask
            for (int j=len/2; j<len; j+=2*slen) {
                int idx = j;
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
                
                for (int k=0; k<slen; k++) {
                    byte[] c = A[idx&nmask].clone();
                    byte[] d = A[idx|mask];
                    addModFn(A[idx], d);
                    A[idx] = cyclicShiftRight(A[idx], 1);
                    
                    subModFn(c, d, 1<<n);
                    A[idx+slen] = c;
                    A[idx+slen] = cyclicShiftRight(A[idx+slen], x+1);
                    idx++;
                }
            }
            
            v--;
            mask *= 2;
        }
        return A;
    }
    
    private static byte[][] extend(byte[][] a, int numBytes) {
        byte[][] b = new byte[a.length][numBytes];
        for (int i=0; i<a.length; i++)
            b[i] = Arrays.copyOf(a[i], numBytes);
        return b;
    }
    
    static void addModFn(byte[] a, byte[] b) {
        int carry = 0;
        for (int i=0; i<a.length; i++) {
            int sum = (a[i]&0xFF) + (b[i]&0xFF) + carry;
            a[i] = (byte)sum;
            carry = sum >>> 8;   // carry>0 if sum>=256 or sum<0
        }
        
        // take a mod Fn by adding any remaining carry bit to the lowest bit
        if (carry > 0) {
            int i = 0;
            do {
                int sum = (a[i]&0xFF) + 1;
                a[i] = (byte)sum;
                carry = sum >> 8;
                i++;
                if (i >= a.length)
                    i = 0;
            } while (carry > 0);
        }
    }
    
    private static void subModFn(byte[] a, byte[] b, int pow2n) {
        addModFn(a, cyclicShiftLeft(b, pow2n));
    }
    
    private static void addModPow2(byte[] a, byte[] b, int numBits) {
        int numBytes = (numBits+7) / 8;
        int carry = 0;
        int i;
        for (i=0; i<numBytes; i++) {
            int sum = (a[i]&0xFF) + (b[i]&0xFF) + carry;
            a[i] = (byte)sum;
            carry = sum >>> 8;
        }
        a[i-1] &= 0xFF >>> (8-(numBits%8));
        for (; i<a.length; i++)
            a[i] = 0;
    }
    
    static void subModPow2(byte[] a, byte[] b, int numBits) {
        int numBytes = (numBits+7) / 8;
        int carry = 0;
        int i;
        for (i=0; i<numBytes; i++) {
            int diff = (a[i]&0xFF) - (b[i]&0xFF) - carry;
            a[i] = (byte)diff;
            carry = (diff >>> 8) & 1;
        }
        a[i-1] &= 0xFF >>> (8-(numBits%8));
        for (; i<a.length; i++)
            a[i] = 0;
    }
    
    private static void shiftLeft(byte[] a, int numBits) {
        int numBytes = numBits / 8;
        System.arraycopy(a, 0, a, numBytes, a.length-numBytes);
        Arrays.fill(a, 0, numBytes, (byte)0);
        
        numBits = numBits % 8;
        if (numBits != 0) {
            a[a.length-1] <<= numBits;
            for (int i=a.length-1; i>0; i--) {
                a[i] |= (byte)((a[i-1]&0xFF) >>> (8-numBits));
                a[i-1] <<= numBits;
            }
        }
    }
    
    static byte[] cyclicShiftRight(byte[] a, int numBits) {
        byte[] b = new byte[a.length];
        int numBytes = numBits / 8;
        System.arraycopy(a, numBytes, b, 0, a.length-numBytes);
        System.arraycopy(a, 0, b, a.length-numBytes, numBytes);
        
        numBits = numBits % 8;
        if (numBits != 0) {
            byte b0 = b[0];
            b[0] = (byte)((b[0]&0xFF) >> numBits);
            for (int i=1; i<b.length; i++) {
                b[i-1] |= (byte)(b[i] << (8-numBits));
                b[i] = (byte)((b[i]&0xFF) >> numBits);
            }
            b[b.length-1] |= (byte)(b0 << (8-numBits));
        }
        return b;
    }
    
    static byte[] multModFn(byte[] a, byte[] b) {
        byte[] c = mult(a, a.length*8, b, b.length*8);
        // special case: if a=b=Fn-1, a*b mod 2^2^(n+1) will be 0 but a*b mod Fn=1, so set c to 1 in this case
        if (isZero(c) && !isZero(a) && !isZero(b))
            c[0] = 1;
        return c;
    }
    
    private static boolean isZero(byte[] a) {
        for (byte b: a)
            if (b != 0)
                return false;
        return true;
    }
    
    /** left means towards the higher array indices and the higher bits */
    static byte[] cyclicShiftLeft(byte[] a, int numBits) {
        byte[] b = new byte[a.length];
        int numBytes = numBits / 8;
        System.arraycopy(a, 0, b, numBytes, a.length-numBytes);
        System.arraycopy(a, a.length-numBytes, b, 0, numBytes);
        
        numBits = numBits % 8;
        if (numBits != 0) {
            byte bhi = b[b.length-1];
            b[b.length-1] <<= numBits;
            for (int i=b.length-1; i>0; i--) {
                b[i] |= (byte)((b[i-1]&0xFF) >>> (8-numBits));
                b[i-1] <<= numBits;
            }
            b[0] |= (byte)((bhi&0xFF) >>> (8-numBits));
        }
        return b;
    }
    
    static void appendBits(byte[] a, int aBitLength, byte[] b, int bBitLength) {
        int aByteIdx = aBitLength / 8;
        int bit8 = aBitLength % 8;
        
        for (int i=0; i<bBitLength/8; i++) {
            if (bit8 > 0) {
                a[aByteIdx] |= b[i] << bit8;
                aByteIdx++;
                a[aByteIdx] = (byte)((b[i]&0xFF) >>> (8-bit8));
            }
            else {
                a[aByteIdx] = b[i];
                aByteIdx++;
            }
        }
        
        if (bBitLength%8 > 0) {
            int bByteIdx = bBitLength / 8;
            a[aByteIdx] |= b[bByteIdx] << bit8;
            if (bit8 > 0)
                a[aByteIdx+1] = (byte)((b[bByteIdx]&0xFF) >>> (8-bit8));
        }
    }
    
    /** Divides a byte array into pieces <code>bitLength</code> bits long */
    private static byte[][] subdivide(byte[] a, int bitLength) {
        int aByteIdx = 0;
        int aBitIdx = 0;
        int numPieces = (a.length*8+bitLength-1) / bitLength;
        int pieceLength = (bitLength+7) / 8;   // in bytes
        byte[][] b = new byte[numPieces][pieceLength];
        for (int i=0; i<b.length; i++) {
            int bitsRemaining = Math.min(bitLength, a.length*8-i*bitLength);
            int bByteIdx = 0;
            int bBitIdx = 0;
            while (bitsRemaining > 0) {
                int bitsToCopy = Math.min(8-aBitIdx, 8-bBitIdx);
                bitsToCopy = Math.min(bitsRemaining, bitsToCopy);
                int mask = a[aByteIdx] >>> aBitIdx;
                mask &= 0xFF >>> (8-bitsToCopy);
                mask <<= bBitIdx;
                b[i][bByteIdx] |= mask;
                bitsRemaining -= bitsToCopy;
                aBitIdx += bitsToCopy;
                if (aBitIdx >= 8) {
                    aBitIdx -= 8;
                    aByteIdx++;
                }
                bBitIdx += bitsToCopy;
                if (bBitIdx >= 8) {
                    bBitIdx -= 8;
                    bByteIdx++;
                }
            }
        }
        return b;
    }
    
    static byte[] reverse(byte[] a) {
        byte[] b = new byte[a.length];
        for (int i=0; i<a.length; i++)
            b[i] = a[a.length-1-i];
        return b;
    }
}