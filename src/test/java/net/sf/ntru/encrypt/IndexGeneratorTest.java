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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Random;
import java.util.zip.GZIPOutputStream;

import org.junit.Before;
import org.junit.Test;

public class IndexGeneratorTest {
    private EncryptionParameters params;
    private byte[] seed;
    private IndexGenerator ig;
    private int[] indices;
    
    @Before
    public void setup() {
        seed = new byte[100];
        new Random().nextBytes(seed);
        params = EncryptionParameters.APR2011_743;
        ig = new IndexGenerator(seed, params);
        indices = initIndices();
    }
    
    private int[] initIndices() {
        int[] indices = new int[1000];
        for (int i=0; i<indices.length; i++)
            indices[i] = ig.nextIndex();
        return indices;
    }
    
    /** Tests the output of {@link IndexGenerator} for randomness. */
    @Test
    public void testRandomness() throws IOException {
        // test compressibility
        BigInteger N = BigInteger.valueOf(params.N);
        BigInteger b = BigInteger.ZERO;
        for (int i: indices)
            b = b.multiply(N).add(BigInteger.valueOf(indices[i]));
        byte[] uncompressed = b.toByteArray();
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        GZIPOutputStream os = new GZIPOutputStream(byteStream);
        os.write(uncompressed);
        os.close();
        byte[] compressed = byteStream.toByteArray();
        int compressedLength = compressed.length;
        compressedLength -= 10;   // remove the gzip header
        compressedLength -= 8;   // remove the gzip footer
        assertTrue(compressedLength > 0.95*uncompressed.length);
        
        // test average and standard deviation
        double avg = 0;
        for (int i: indices)
            avg += i;
        avg /= indices.length;
        assertTrue(Math.abs(params.N/2.0-avg) < 30);
        double dev = 0;
        for (int i: indices)
            dev += (i-avg) * (i-avg);
        dev /= indices.length - 1;
        dev = Math.sqrt(dev);
        assertTrue(Math.abs(params.N/Math.sqrt(12)-dev) < 15);
    }
    
    @Test
    public void testRepeatability() {
        ig = new IndexGenerator(seed, params);
        int[] indices2 = initIndices();
        assertArrayEquals(indices, indices2);
    }
    
    @Test
    public void testRange() {
        for (int i: indices)
            assertTrue(i>=0 && i<params.N);
    }
}