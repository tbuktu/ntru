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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import net.sf.ntru.IndexGenerator.BitString;

import org.junit.Test;

public class BitStringTest {
    
    @Test
    public void testAppendBitsByteArray() {
        BitString bs = new BitString();
        bs.appendBits((byte)78);
        assertBitStringEquals(bs, new byte[] {78});
        bs.appendBits((byte)-5);
        assertBitStringEquals(bs, new byte[] {78, -5});
        bs.appendBits((byte)127);
        assertBitStringEquals(bs, new byte[] {78, -5, 127});
        bs.appendBits((byte)0);
        assertBitStringEquals(bs, new byte[] {78, -5, 127, 0});
        bs.appendBits((byte)100);
        assertBitStringEquals(bs, new byte[] {78, -5, 127, 0, 100});
    }
    
    private void assertBitStringEquals(BitString bs, byte[] arr) {
        assertTrue(bs.bytes.length >= arr.length);
        arr = Arrays.copyOf(arr, bs.bytes.length);
        assertArrayEquals(arr, bs.bytes);
    }
    
    @Test
    public void testGetTrailing() {
        BitString bs = new BitString();
        bs.appendBits((byte)78);
        BitString bs2 = bs.getTrailing(3);
        assertBitStringEquals(bs2, new byte[] {6});
        
        bs = new BitString();
        bs.appendBits((byte)78);
        bs.appendBits((byte)-5);
        bs2 = bs.getTrailing(9);
        assertBitStringEquals(bs2, new byte[] {78, 1});
        
        bs2.appendBits((byte)100);
        assertBitStringEquals(bs2, new byte[] {78, -55});
        bs = bs2.getTrailing(13);
        assertBitStringEquals(bs, new byte[] {78, 9});
        bs2 = bs2.getTrailing(11);
        assertBitStringEquals(bs2, new byte[] {78, 1});
        
        bs2.appendBits((byte)100);
        assertBitStringEquals(bs2, new byte[] {78, 33, 3});
        bs2 = bs2.getTrailing(16);
        assertBitStringEquals(bs2, new byte[] {78, 33});
    }
    
    @Test
    public void testGetLeadingAsInt() {
        BitString bs = new BitString();
        bs.appendBits((byte)78);
        bs.appendBits((byte)42);
        assertEquals(1, bs.getLeadingAsInt(3));
        assertEquals(84, bs.getLeadingAsInt(9));
        assertEquals(338, bs.getLeadingAsInt(11));
        
        BitString bs2 = bs.getTrailing(11);
        assertBitStringEquals(bs2, new byte[] {78, 2});
        assertEquals(590, bs2.getLeadingAsInt(11));
        assertEquals(9, bs2.getLeadingAsInt(5));
        
        bs2.appendBits((byte)115);
        assertEquals(230, bs2.getLeadingAsInt(9));
        assertEquals(922, bs2.getLeadingAsInt(11));
        
        bs2.appendBits((byte)-36);
        assertEquals(55, bs2.getLeadingAsInt(6));
    }
}