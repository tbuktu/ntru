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