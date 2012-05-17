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

package net.sf.ntru.encrypt;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import net.sf.ntru.exception.NtruException;

/**
 * An implementation of the Index Generation Function IGF-2
 * in IEEE P1363.1 section 8.4.2.1.
 */
public class IndexGenerator {
    private int N;
    private int c;
    private byte[] Z;
    private int remLen;
    private BitString buf;
    private int counter;
    private MessageDigest hashAlg;
    private int hLen;
    
    /**
     * Constructs a new index generator.
     * @param seed a seed of arbitrary length to initialize the index generator with
     * @param params NtruEncrypt parameters
     * @throws NtruException if the JRE doesn't implement the specified hash algorithm
     */
    IndexGenerator(byte[] seed, EncryptionParameters params) {
        N = params.N;
        c = params.c;
        int minCallsR = params.minCallsR;
        
        try {
            hashAlg = MessageDigest.getInstance(params.hashAlg);
        } catch (NoSuchAlgorithmException e) {
            throw new NtruException(e);
        }
        hLen = hashAlg.getDigestLength();   // hash length
        
        Z = seed;
        counter = 0;
        buf = new BitString();
        while (counter < minCallsR) {
            ByteBuffer hashInput = ByteBuffer.allocate(Z.length + 4);
            hashInput.put(Z);
            hashInput.putInt(counter);
            byte[] H = hashAlg.digest(hashInput.array());
            buf.appendBits(H);
            counter++;
        }
        remLen = minCallsR * 8 * hLen;
    }
    
    /**
     * Returns a number <code>i</code> such that <code>0 &lt;= i &lt; N</code>.
     * @return
     */
    public int nextIndex() {
        while (true) {
            if (remLen < c) {
                BitString M = buf.getTrailing(remLen);
                int tmpLen = c - remLen;
                int cThreshold = counter + (tmpLen+hLen-1)/hLen;
                while (counter < cThreshold) {
                    ByteBuffer hashInput = ByteBuffer.allocate(Z.length + 4);
                    hashInput.put(Z);
                    hashInput.putInt(counter);
                    byte[] H = hashAlg.digest(hashInput.array());
                    M.appendBits(H);
                    counter++;
                    remLen += 8 * hLen;
                }
                buf = M;
            }
            
            int i = buf.getLeadingAsInt(c);   // assume c<32
            buf.truncate(c);
            remLen -= c;
            if (i < (1<<c)-((1<<c)%N))
                return i % N;
        }
    }
    
    /**
     * Represents a string of bits and supports appending, reading the head, and reading the tail.
     */
    static class BitString {
        private static int INITIAL_SIZE = 4;
        
        byte[] bytes = new byte[INITIAL_SIZE];
        private int numBytes;   // includes the last byte even if only some of its bits are used
        private int lastByteBits;   // lastByteBits <= 8
        
        /**
         * Appends all bits in a byte array to the end of the bit string.
         * @param bytes a byte array
         */
        private void appendBits(byte[] bytes) {
            for (byte b: bytes)
                appendBits(b);
        }
        
        /**
         * Appends all bits in a byte to the end of the bit string.
         * @param b a byte
         */
        void appendBits(byte b) {
            if (numBytes == bytes.length)
                bytes = Arrays.copyOf(bytes, Math.max(2*bytes.length, INITIAL_SIZE));
            
            if (numBytes == 0) {
                numBytes = 1;
                bytes[0] = b;
                lastByteBits = 8;
            }
            else if (lastByteBits == 8)
                bytes[numBytes++] = b;
            else {
                int s = 8 - lastByteBits;
                bytes[numBytes-1] |= (b&0xFF) << lastByteBits;
                bytes[numBytes++] = (byte)((b&0xFF) >> s);
            }
        }
        
        /**
         * Returns the last <code>numBits</code> bits from the end of the bit string.
         * @param numBits number of bits
         * @return a new <code>BitString</code> of length <code>numBits</code>
         */
        BitString getTrailing(int numBits) {
            BitString newStr = new BitString();
            newStr.numBytes = (numBits+7) / 8;
            newStr.bytes = new byte[newStr.numBytes];
            for (int i=0; i<newStr.numBytes; i++)
                newStr.bytes[i] = bytes[i];
            
            newStr.lastByteBits = numBits % 8;
            if (newStr.lastByteBits == 0)
                newStr.lastByteBits = 8;
            else {
                int s = 32 - newStr.lastByteBits;
                newStr.bytes[newStr.numBytes-1] = (byte)(newStr.bytes[newStr.numBytes-1] << s >>> s);
            }
            
            return newStr;
        }
        
        /**
         * Returns up to 32 bits from the beginning of the bit string.
         * @param numBits number of bits
         * @return an <code>int</code> whose lower <code>numBits</code> bits are the beginning of the bit string
         */
        int getLeadingAsInt(int numBits) {
            int startBit = (numBytes-1)*8 + lastByteBits - numBits;
            int startByte = startBit / 8;
            
            int startBitInStartByte = startBit % 8;
            int sum = (bytes[startByte]&0xFF) >>> startBitInStartByte;
            int shift = 8 - startBitInStartByte;
            for (int i=startByte+1; i<numBytes-1; i++) {
                sum |= (bytes[i]&0xFF) << shift;
                shift += 8;
            }
            int finalBits = numBits - shift;   // #bits in the final byte
            sum |= (bytes[numBytes-1] & (0xFF>>>(8-finalBits))) << shift;   // append finalBits more bits
            
            return sum;
        }
        
        /**
         * Removes a given number of bits from the end of the bit string.
         * @param numBits number of bits to remove
         */
        void truncate(int numBits) {
            numBytes -= numBits / 8;
            lastByteBits -= numBits % 8;
            if (lastByteBits < 0) {
                lastByteBits += 8;
                numBytes--;
            }
        }
    }
}