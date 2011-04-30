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
    private byte[] buf;
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
    
    int nextIndex() {
        if (!initialized) {
            buf = new byte[] {};
            while (counter < minCallsR) {
                ByteBuffer hashInput = ByteBuffer.allocate(seed.length + 4);
                hashInput.put(seed);
                hashInput.putInt(counter);
                byte[] hash = hashAlg.digest(hashInput.array());
                buf = append(buf, hash);
                counter++;
            }
            totLen = minCallsR * hLen;
            remLen = totLen;
            initialized = true;
        }
        
        while (true) {
            totLen += c;
            byte[] M = Arrays.copyOfRange(buf, buf.length-remLen, buf.length);
            if (remLen < c) {
                int tmpLen = c - remLen;
                int cThreshold = counter + (tmpLen+hLen-1)/hLen;
                byte[] hash = new byte[] {};
                while (counter < cThreshold) {
                    ByteBuffer hashInput = ByteBuffer.allocate(seed.length + 4);
                    hashInput.put(seed);
                    hashInput.putInt(counter);
                    hash = hashAlg.digest(hashInput.array());
                    M = append(M, hash);
                    counter++;
                    if (tmpLen > hLen)
                        tmpLen -= hLen;
                }
                remLen = hLen - tmpLen;
                buf = hash;
            }
            else
                remLen -= c;
            
            int i = ByteBuffer.wrap(M).getInt();   // assume c<32
            i &= 0x7FFFFFFFL;
            i = i & ((1<<c)-1);   // only keep the low c bits
            if (i < (1<<c)-((1<<c)%N))
                return i;
        }
    }
    
    private byte[] append(byte[] a, byte[] b) {
        byte[] c = Arrays.copyOf(a, a.length+b.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }
}