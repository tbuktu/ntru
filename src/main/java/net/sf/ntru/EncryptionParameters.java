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

public class EncryptionParameters {
    public static final EncryptionParameters EES1087EP2 = new EncryptionParameters(1087, 2048, 120, 120, 256, 13, 25, 14, new byte[] {0, 6, 3}, true);   // security>256, optimized for key size
    public static final EncryptionParameters EES1171EP1 = new EncryptionParameters(1171, 2048, 106, 106, 256, 13, 20, 15, new byte[] {0, 6, 4}, true);   // security>256, key size / speed tradeoff
    public static final EncryptionParameters EES1499EP1 = new EncryptionParameters(1499, 2048, 79, 79, 256, 13, 17, 19, new byte[] {0, 6, 5}, true);   // security>256, optimized for speed
    public static final EncryptionParameters APR2011_439 = new EncryptionParameters(439, 2048, 146, 130, 128, 9, 32, 9, new byte[] {0, 7, 101}, true);   // security=128
    public static final EncryptionParameters APR2011_743 = new EncryptionParameters(743, 2048, 248, 220, 256, 10, 27, 14, new byte[] {0, 7, 105}, false);   // security=256
    
    int N, q, df, dr, dg, llen, maxMsgLenBytes, db, bufferLenBits, bufferLenTrits, dm0, pkLen, c, minCallsR, minCallsMask;
    byte[] oid;
    boolean sparse;   // whether to treat ternary polynomials as sparsely populated
    
    public EncryptionParameters(int N, int q, int df, int dm0, int db, int c, int minCallsR, int minCallsMask, byte[] oid, boolean sparse) {
        this.N = N;
        this.q = q;
        this.df = df;
        dr = df;
        dg = N / 3;
        llen = 1;   // ceil(log2(maxMsgLenBytes))
        this.db = db;
        maxMsgLenBytes = N*3/2/8 - llen - db/8;
        bufferLenBits = (N*3/2+7)/8*8;   // one byte more than p1363.1 says
        bufferLenTrits = N - 1;
        this.dm0 = dm0;
        pkLen = db / 2;
        this.c = c;
        this.minCallsR = minCallsR;
        this.minCallsMask = minCallsMask;
        this.oid = oid;
    }
}