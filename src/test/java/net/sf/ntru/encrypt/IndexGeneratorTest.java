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

import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Random;
import java.util.zip.GZIPOutputStream;

import org.junit.Test;

public class IndexGeneratorTest {
    
    /** Tests the output of {@link IndexGenerator} for randomness. */
    @Test
    public void test() throws IOException {
        byte[] seed = new byte[100];
        new Random().nextBytes(seed);
        EncryptionParameters params = EncryptionParameters.APR2011_743;
        IndexGenerator ig = new IndexGenerator(seed, params);
        
        int[] indices = new int[1000];
        for (int i=0; i<indices.length; i++)
            indices[i] = ig.nextIndex();
        
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
}