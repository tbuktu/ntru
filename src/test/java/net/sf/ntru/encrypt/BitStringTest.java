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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import net.sf.ntru.encrypt.IndexGenerator.BitString;

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