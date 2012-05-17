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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class PassphraseBasedPRNGTest {
    
    @Test
    public void testNext() {
        PassphraseBasedPRNG rng = createRng();
        
        assertTrue(rng.next(1) < 2);
        assertTrue(rng.next(1) >= 0);
        assertTrue(rng.next(8) < 256);
        assertTrue(rng.next(8) >= 0);
        assertTrue(rng.next(11) < 2048);
        assertTrue(rng.next(11) >= 0);
        assertTrue(rng.next(31) >= 0);
    }
    
    @Test
    public void testCreateBranch() {
        PassphraseBasedPRNG rng1 = createRng();
        PassphraseBasedPRNG rng2 = rng1.createBranch();
        
        byte[] data1 = new byte[32];
        rng2.nextBytes(data1);
        
        rng1 = createRng();
        rng2 = rng1.createBranch();
        byte[] data2 = new byte[32];
        rng2.nextBytes(data2);
        
        assertArrayEquals(data1, data2);
    }
    
    private PassphraseBasedPRNG createRng() {
        return new PassphraseBasedPRNG("my secret passphrase".toCharArray(), new byte[] {-37, 103, 50, -91, 2, -43, -106, 65});
    }
}