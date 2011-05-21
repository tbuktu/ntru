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

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

// implementation of IGF-2
class IndexGenerator {
    private byte[] seed;
    private int N;
    private int c;
    private int minCallsR;
    private int totLen;
    private int remLen;
    private BitString buf;
    private int counter;
    private boolean initialized;
    private MessageDigest hashAlg;
    private int hLen;
    
    IndexGenerator(byte[] seed, EncryptionParameters params) throws NoSuchAlgorithmException {
        this.seed = seed;
        N = params.N;
        c = params.c;
        minCallsR = params.minCallsR;
        
        totLen = 0;
        remLen = 0;
        counter = 0;
        hashAlg = MessageDigest.getInstance("SHA-512");
        hLen = 64;   // hash length
        initialized = false;
    }
    
    /**
     * returns a number i such that 0<=i<N
     * @return
     */
    int nextIndex() {
        if (!initialized) {
            buf = new BitString();
            while (counter < minCallsR) {
                ByteBuffer hashInput = ByteBuffer.allocate(seed.length + 4);
                hashInput.put(seed);
                hashInput.putInt(counter);
                byte[] hash = hashAlg.digest(hashInput.array());
                buf.appendBits(hash);
                counter++;
            }
            totLen = minCallsR * 8 * hLen;
            remLen = totLen;
            initialized = true;
        }
        
        while (true) {
            totLen += c;
            BitString M = buf.getTrailing(remLen);
            if (remLen < c) {
                int tmpLen = c - remLen;
                int cThreshold = counter + (tmpLen+hLen-1)/hLen;
                byte[] hash = new byte[] {};
                while (counter < cThreshold) {
                    ByteBuffer hashInput = ByteBuffer.allocate(seed.length + 4);
                    hashInput.put(seed);
                    hashInput.putInt(counter);
                    hash = hashAlg.digest(hashInput.array());
                    M.appendBits(hash);
                    counter++;
                    if (tmpLen > 8*hLen)
                        tmpLen -= 8*hLen;
                }
                remLen = 8*hLen - tmpLen;
                buf = new BitString();
                buf.appendBits(hash);
            }
            else
                remLen -= c;
            
            int i = M.getLeadingAsInt(c);   // assume c<32
            if (i < (1<<c)-((1<<c)%N))
                return i % N;
        }
    }
    
    static class BitString {
        byte[] bytes = new byte[4];
        int numBytes;   // includes the last byte even if only some of its bits are used
        int lastByteBits;   // lastByteBits <= 8
        
        void appendBits(byte[] bytes) {
            for (byte b: bytes)
                appendBits(b);
        }
        
        void appendBits(byte b) {
            if (numBytes == bytes.length)
                bytes = Arrays.copyOf(bytes, 2*bytes.length);
            
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
        
        int getLeadingAsInt(int numBits) {
            int startBit = (numBytes-1)*8 + lastByteBits - numBits;
            int startByte = startBit / 8;
            
            int startBitInStartByte = startBit % 8;
            int sum = (bytes[startByte]&0xFF) >>> startBitInStartByte;
            int shift = 8 - startBitInStartByte;
            for (int i=startByte+1; i<numBytes; i++) {
                sum |= (bytes[i]&0xFF) << shift;
                shift += 8;
            }
            
            return sum;
        }
    }
}