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

class IndexGenerator {
    private byte[] seed;
    private int N;
    private int c;
    private int minCallsR;
    private int totLen;
    private int remLen;
    private ByteBuffer buf;
    private int counter;
    private int nLen;
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
        nLen = (int)Math.ceil(Math.log(N)/8);
        hashAlg = MessageDigest.getInstance("SHA-512");
        hLen = 64;   // hash length
        initialized = false;
    }
    
    int nextIndex() {
        if (!initialized) {
            buf = ByteBuffer.allocate(minCallsR * hLen);
            while (counter < minCallsR) {
                ByteBuffer hashInput = ByteBuffer.allocate(seed.length + 4);
                hashInput.put(seed);
                hashInput.putInt(counter);
                byte[] hash = hashAlg.digest(hashInput.array());
                buf.put(hash);
                counter++;
            }
            totLen = minCallsR * hLen;
            remLen = totLen;
            initialized = true;
        }
        
        while (true) {
            totLen += nLen;
            if (remLen < nLen) {
                byte[] bufArr = buf.array();
                ByteBuffer M = ByteBuffer.allocate(remLen + hLen);
                M.put(bufArr, bufArr.length-remLen-1, remLen);
                int tmpLen = nLen - remLen;
                int cThreshold = counter + (tmpLen+hLen-1)/hLen;
                ByteBuffer hashInput = ByteBuffer.allocate(seed.length + 4);
                hashInput.put(seed);
                hashInput.putInt(counter);
                byte[] hash = hashAlg.digest(hashInput.array());
                M.put(hash);
                while (counter < cThreshold) {
                    counter++;
                    if (tmpLen > hLen)
                        tmpLen -= hLen;
                }
                remLen = hLen - tmpLen;
                buf = ByteBuffer.allocate(minCallsR * hLen);
                buf.put(hash);
            }
            else
                remLen -= nLen;
            
            buf.rewind();
            int i = buf.getInt();   // assume c<32
            i = (i << c) >> c;   // only keep the low c bits
            if (i <= (2<<c)-((2<<c)%N))
                return i;
        }
    }
}