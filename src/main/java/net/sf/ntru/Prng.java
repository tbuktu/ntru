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

// deterministic pseudo-random generator
public class Prng {
    private int counter;
    private byte[] seed;
    private MessageDigest hashAlg;
    
    Prng(byte[] seed) throws NoSuchAlgorithmException {
        counter = 0;
        this.seed = seed;
        hashAlg = MessageDigest.getInstance("SHA-512");
    }
    
    byte[] nextBytes(int n) {
        ByteBuffer buf = ByteBuffer.allocate(n);
        
        while (buf.hasRemaining()) {
            ByteBuffer cbuf = ByteBuffer.allocate(seed.length + 4);
            cbuf.put(seed);
            cbuf.putInt(counter);
            byte[] hash = hashAlg.digest(cbuf.array());
            
            if (buf.remaining() < hash.length)
                buf.put(hash, 0, buf.remaining());
            else
                buf.put(hash);
            counter++;
        }
        
        return buf.array();
    }
}