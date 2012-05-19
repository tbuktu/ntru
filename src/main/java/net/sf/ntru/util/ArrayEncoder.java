/**
 * Copyright (c) 2011, Tim Buktu
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package net.sf.ntru.util;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Arrays;

import net.sf.ntru.exception.NtruException;

/**
 * Converts a coefficient array to a compact byte array and vice versa.
 */
public class ArrayEncoder {
    /**
     * Bit string to coefficient conversion table from P1363.1. Also found at
     * {@link http://stackoverflow.com/questions/1562548/how-to-make-a-message-into-a-polynomial}
     * <p/>
     * Convert each three-bit quantity to two ternary coefficients as follows, and concatenate the resulting
     * ternary quantities to obtain [the output].
     * <p/>
     * <code>
     * {0, 0, 0} -> {0, 0}<br/>
     * {0, 0, 1} -> {0, 1}<br/>
     * {0, 1, 0} -> {0, -1}<br/>
     * {0, 1, 1} -> {1, 0}<br/>
     * {1, 0, 0} -> {1, 1}<br/>
     * {1, 0, 1} -> {1, -1}<br/>
     * {1, 1, 0} -> {-1, 0}<br/>
     * {1, 1, 1} -> {-1, 1}<br/>
     * </code>
     */
    private static final int[] COEFF1_TABLE = {0, 0, 0, 1, 1, 1, -1, -1};
    private static final int[] COEFF2_TABLE = {0, 1, -1, 0, 1, -1, 0, 1};
    /**
     * Coefficient to bit string conversion table from P1363.1. Also found at
     * {@link http://stackoverflow.com/questions/1562548/how-to-make-a-message-into-a-polynomial}
     * <p/>
     * Convert each set of two ternary coefficients to three bits as follows, and concatenate the resulting bit
     * quantities to obtain [the output]:
     * <p/>
     * <code>
     * {-1, -1} -> set "fail" to 1 and set bit string to {1, 1, 1}
     * {-1, 0} -> {1, 1, 0}<br/>
     * {-1, 1} -> {1, 1, 1}<br/>
     * {0, -1} -> {0, 1, 0}<br/>
     * {0, 0} -> {0, 0, 0}<br/>
     * {0, 1} -> {0, 0, 1}<br/>
     * {1, -1} -> {1, 0, 1}<br/>
     * {1, 0} -> {0, 1, 1}<br/>
     * {1, 1} -> {1, 0, 0}<br/>
     * </code>
     */
    private static final int[] BIT1_TABLE = {1, 1, 1, 0, 0, 0, 1, 0, 1};
    private static final int[] BIT2_TABLE = {1, 1, 1, 1, 0, 0, 0, 1, 0};
    private static final int[] BIT3_TABLE = {1, 0, 1, 0, 0, 1, 1, 1, 0};
    private static final BigInteger THREE = BigInteger.valueOf(3);
    
    /**
     * Encodes an int array whose elements are between 0 and <code>q</code>,
     * to a byte array leaving no gaps between bits.<br/>
     * <code>q</code> must be a power of 2.
     * @param a the input array
     * @param q the modulus
     * @return the encoded array
     */
    public static byte[] encodeModQ(int[] a, int q) {
        int bitsPerCoeff = 31 - Integer.numberOfLeadingZeros(q);
        int numBits = a.length * bitsPerCoeff;
        int numBytes = (numBits+7) / 8;
        byte[] data = new byte[numBytes];
        int bitIndex = 0;
        int byteIndex = 0;
        for (int i=0; i<a.length; i++)
            for (int j=0; j<bitsPerCoeff; j++) {
                int currentBit = (a[i] >> j) & 1;
                data[byteIndex] |= currentBit << bitIndex;
                if (bitIndex == 7) {
                    bitIndex = 0;
                    byteIndex++;
                }
                else
                    bitIndex++;
            }
        return data;
    }
    
    /**
     * Like {@link #encodeModQ(int[], int)} but only returns the first <code>numBytes</code>
     * bytes of the encoding.
     * @param a the input array
     * @param q the modulus
     * @param numBytes
     * @return the encoded array
     */
    public static byte[] encodeModQTrunc(int[] a, int q, int numBytes) {
        int bitsPerCoeff = 31 - Integer.numberOfLeadingZeros(q);
        byte[] data = new byte[numBytes];
        int bitIndex = 0;
        int byteIndex = 0;
        for (int i=0; i<a.length; i++) {
            for (int j=0; j<bitsPerCoeff; j++) {
                int currentBit = (a[i] >> j) & 1;
                data[byteIndex] |= currentBit << bitIndex;
                if (bitIndex == 7) {
                    bitIndex = 0;
                    byteIndex++;
                    if (byteIndex >= numBytes)
                        return data;
                }
                else
                    bitIndex++;
            }
        }
        return null;
    }
    
    /**
     * Decodes a <code>byte</code> array encoded with {@link #encodeModQ(int[], int)} back to an <code>int</code> array.<br/>
     * <code>N</code> is the number of coefficients. <code>q</code> must be a power of <code>2</code>.<br/>
     * Ignores any excess bytes.
     * @param data an encoded ternary polynomial
     * @param N number of coefficients
     * @param q
     * @return an array containing <code>N</code> coefficients between <code>0</code> and <code>q-1</code>
     */
    public static int[] decodeModQ(byte[] data, int N, int q) {
        int[] coeffs = new int[N];
        int bitsPerCoeff = 31 - Integer.numberOfLeadingZeros(q);
        int mask = -1 >>> (32-bitsPerCoeff);   // for truncating values to bitsPerCoeff bits
        int byteIndex = 0;
        int bitIndex = 0;   // next bit in data[byteIndex]
        int coeffBuf = 0;   // contains (bitIndex) bits
        int coeffBits = 0;   // length of coeffBuf
        int coeffIndex = 0;   // index into coeffs
        while (coeffIndex < N) {
            // copy bitsPerCoeff or more into coeffBuf
            while (coeffBits < bitsPerCoeff) {
                coeffBuf += (data[byteIndex]&0xFF) << coeffBits;
                coeffBits += 8 - bitIndex;
                byteIndex++;
                bitIndex = 0;
            }
            
            // low bitsPerCoeff bits = next coefficient
            coeffs[coeffIndex] = coeffBuf & mask;
            coeffIndex++;
            
            coeffBuf >>>= bitsPerCoeff;
            coeffBits -= bitsPerCoeff;
        }
        return coeffs;
    }
    
    /**
     * Decodes data encoded with {@link #encodeModQ(int[], int)} back to an <code>int</code> array.<br/>
     * <code>N</code> is the number of coefficients. <code>q</code> must be a power of <code>2</code>.<br/>
     * Ignores any excess bytes.
     * @param is an encoded ternary polynomial
     * @param N number of coefficients
     * @param q
     * @return the decoded polynomial
     */
    public static int[] decodeModQ(InputStream is, int N, int q) throws IOException {
        int qBits = 31 - Integer.numberOfLeadingZeros(q);
        int size = (N*qBits+7) / 8;
        byte[] arr = ArrayEncoder.readFullLength(is, size);
        return decodeModQ(arr, N, q);
    }
    
    /**
     * Decodes a <code>byte</code> array encoded with {@link #encodeMod3Sves(int[])} back to an <code>int</code> array
     * with <code>N</code> coefficients between <code>-1</code> and <code>1</code>.<br/>
     * Ignores any excess bytes.<br/>
     * See P1363.1 section 9.2.2.
     * @param data an encoded ternary polynomial
     * @param N number of coefficients
     * @param skipFirst whether to leave the constant coefficient zero and start populating at the linear coefficient
     * @return the decoded coefficients
     */
    public static int[] decodeMod3Sves(byte[] data, int N, boolean skipFirst) {
        int[] coeffs = new int[N];
        int coeffIndex = skipFirst ? 1 : 0;
        int i = 0;
        while (i<data.length/3*3 && coeffIndex<N-1) {
            // process 24 bits at a time in the outer loop
            int chunk = (data[i++]&0xFF) | ((data[i++]&0xFF)<<8) | ((data[i++]&0xFF)<<16);
            for (int j=0; j<8 && coeffIndex<N-1; j++) {
                // process 3 bits at a time in the inner loop
                int coeffTableIndex = ((chunk&1)<<2) + (chunk&2) + ((chunk&4)>>2);   // low 3 bits in reverse order
                coeffs[coeffIndex++] = COEFF1_TABLE[coeffTableIndex];
                coeffs[coeffIndex++] = COEFF2_TABLE[coeffTableIndex];
                chunk >>= 3;
            }
        }
        return coeffs;
    }
    
    /**
     * Encodes an <code>int</code> array whose elements are between <code>-1</code> and <code>1</code>, to a byte array.
     * <code>coeffs[2*i]</code> and <code>coeffs[2*i+1]</code> must not both equal -1 for any integer </code>i<code>,
     * so this method is only safe to use with arrays produced by {@link #decodeMod3Sves(byte[], int)}.<br/>
     * See P1363.1 section 9.2.3.
     * @param arr
     * @param skipFirst whether to skip the constant coefficient
     * @return the encoded array
     * @throws NtruException if <code>(-1,-1)</code> is encountered
     */
    public static byte[] encodeMod3Sves(int[] arr, boolean skipFirst) {
        int numBits = (arr.length*3+1) / 2;
        int numBytes = (numBits+7) / 8;
        byte[] data = new byte[numBytes];
        int byteIndex = 0;
        int start = skipFirst ? 1 : 0;
        int end = skipFirst ? (arr.length-1)|1 : arr.length/2*2;   // if there is an odd number of coeffs, throw away the highest one
        int i = start;
        while (i < end) {
            // process 24 bits at a time in the outer loop
            int chunk = 0;
            int chunkBits = 0;   // #bits in the chunk
            while (chunkBits<24 && i<end) {
                int coeff1 = arr[i++] + 1;
                int coeff2 = arr[i++] + 1;
                if (coeff1==0 && coeff2==0)
                    throw new NtruException("Illegal encoding!");
                
                int bitTableIndex = coeff1*3 + coeff2;
                chunk |= BIT1_TABLE[bitTableIndex] << chunkBits++;
                chunk |= BIT2_TABLE[bitTableIndex] << chunkBits++;
                chunk |= BIT3_TABLE[bitTableIndex] << chunkBits++;
            }
            
            data[byteIndex++] = (byte)(chunk & 0xFF);
            if (byteIndex < data.length)
                data[byteIndex++] = (byte)((chunk>>8) & 0xFF);
            if (byteIndex < data.length)
                data[byteIndex++] = (byte)((chunk>>16) & 0xFF);
        }
        return data;
    }
    
    /**
     * Encodes an <code>int</code> array whose elements are between <code>-1</code> and <code>1</code>, to a byte array.
     * @return the encoded array
     */
    public static byte[] encodeMod3Tight(int[] intArray) {
        BigInteger sum = BigInteger.ZERO;
        for (int i=intArray.length-1; i>=0; i--) {
            sum = sum.multiply(THREE);
            sum = sum.add(BigInteger.valueOf(intArray[i]+1));
        }
        
        int size = (THREE.pow(intArray.length).bitLength()+7) / 8;
        byte[] arr = sum.toByteArray();
        
        if (arr.length < size) {
            // pad with leading zeros so arr.length==size
            byte[] arr2 = new byte[size];
            System.arraycopy(arr, 0, arr2, size-arr.length, arr.length);
            return arr2;
        }
        
        if (arr.length > size)
            // drop sign bit
            arr = Arrays.copyOfRange(arr, 1, arr.length);
        return arr;
    }
    
    /**
     * Converts a byte array produced by {@link #encodeMod3Tight(int[])} back to an <code>int</code> array.
     * @param b a byte array
     * @param N number of coefficients
     * @return the decoded array
     */
    public static int[] decodeMod3Tight(byte[] b, int N) {
        BigInteger sum = new BigInteger(1, b);
        int[] coeffs = new int[N];
        for (int i=0; i<N; i++) {
            coeffs[i] = sum.mod(THREE).intValue() - 1;
            if (coeffs[i] > 1)
                coeffs[i] -= 3;
            sum = sum.divide(THREE);
        }
        return coeffs;
    }
    
    /**
     * Converts data produced by {@link #encodeMod3Tight(int[])} back to an <code>int</code> array.
     * @param is an input stream containing the data to decode
     * @param N number of coefficients
     * @return the decoded array
     */
    public static int[] decodeMod3Tight(InputStream is, int N) throws IOException {
        int size = (int)Math.ceil(N * Math.log(3) / Math.log(2) / 8);
        byte[] arr = ArrayEncoder.readFullLength(is, size);
        return decodeMod3Tight(arr, N);
    }
    
    /**
     * Reads a given number of bytes from an <code>InputStream</code>.
     * If there are not enough bytes in the stream, an <code>IOException</code>
     * is thrown.
     * @param is
     * @param length
     * @return an array of length <code>length</code>
     * @throws IOException
     */
    public static byte[] readFullLength(InputStream is, int length) throws IOException {
        byte[] arr = new byte[length];
        if (is.read(arr) != arr.length)
            throw new IOException("Not enough bytes to read.");
        return arr;
    }
    
    /** Concatenates two or more <code>byte</code> arrays. */
    public static byte[] concatenate(byte[]... arrays) {
        int totalLength = 0;
        for (byte[] arr: arrays)
            totalLength += arr.length;
        byte[] bigArr = new byte[totalLength];
        
        int idx = 0;
        for (byte[] arr: arrays) {
            System.arraycopy(arr, 0, bigArr, idx, arr.length);
            idx += arr.length;
        }
        
        return bigArr;
    }
    
    /**
     * Copies the lower two bytes of an <code>int</code> into a <code>byte</code> array.
     * @param i
     * @return
     */
    public static byte[] toByteArray(int i) {
        byte[] arr = new byte[2];
        arr[0] = (byte)(i>>>8);
        arr[1] = (byte)(i&0xFF);
        return arr;
    }
}