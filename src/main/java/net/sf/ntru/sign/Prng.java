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

package net.sf.ntru.sign;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import net.sf.ntru.exception.NtruException;

/**
 * An implementation of the deterministic pseudo-random generator in EESS section 3.7.3.1
 */
public class Prng {
    private int counter;
    private byte[] seed;
    private MessageDigest hashAlg;
    
    /**
     * Constructs a new PRNG and seeds it with a byte array.
     * @param seed a seed
     * @param hashAlg the hash algorithm to use
     * @throws NtruException if the JRE doesn't implement the specified hash algorithm
     */
    Prng(byte[] seed, String hashAlg) {
        counter = 0;
        this.seed = seed;
        try {
            this.hashAlg = MessageDigest.getInstance(hashAlg);
        } catch (NoSuchAlgorithmException e) {
            throw new NtruException(e);
        }
    }
    
    /**
     * Returns <code>n</code> random bytes
     * @param n number of bytes to return
     * @return the next <code>n</code> random bytes
     */
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