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

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

import net.sf.ntru.polynomial.DenseTernaryPolynomial;
import net.sf.ntru.polynomial.SparseTernaryPolynomial;

/**
 * A set of parameters for NtruEncrypt. Several predefined parameter sets are available and new ones can be created as well.
 */
public class EncryptionParameters implements Cloneable {
    /** A conservative (in terms of security) parameter set that gives 256 bits of security and is optimized for key size. */
    public static final EncryptionParameters EES1087EP2 = new EncryptionParameters(1087, 2048, 120, 120, 256, 13, 25, 14, new byte[] {0, 6, 3}, true, false);
    
    /** A conservative (in terms of security) parameter set that gives 256 bits of security and is a tradeoff between key size and encryption/decryption speed. */
    public static final EncryptionParameters EES1171EP1 = new EncryptionParameters(1171, 2048, 106, 106, 256, 13, 20, 15, new byte[] {0, 6, 4}, true, false);
    
    /** A conservative (in terms of security) parameter set that gives 256 bits of security and is optimized for encryption/decryption speed. */
    public static final EncryptionParameters EES1499EP1 = new EncryptionParameters(1499, 2048, 79, 79, 256, 13, 17, 19, new byte[] {0, 6, 5}, true, false);
    
    /** A parameter set that gives 128 bits of security. */
    public static final EncryptionParameters APR2011_439 = new EncryptionParameters(439, 2048, 146, 130, 128, 9, 32, 9, new byte[] {0, 7, 101}, true, false);
    
    /** Like <code>APR2011_439</code>, this parameter set gives 128 bits of security but uses product-form polynomials and <code>f=1+pF</code>. */
    public static final EncryptionParameters APR2011_439_FAST = new EncryptionParameters(439, 2048, 9, 8, 5, 130, 128, 9, 32, 9, new byte[] {0, 7, 101}, true, true);
    
    /** A parameter set that gives 256 bits of security. */
    public static final EncryptionParameters APR2011_743 = new EncryptionParameters(743, 2048, 248, 220, 256, 10, 27, 14, new byte[] {0, 7, 105}, false, false);
    
    /** Like <code>APR2011_743</code>, this parameter set gives 256 bits of security but uses product-form polynomials and <code>f=1+pF</code>. */
    public static final EncryptionParameters APR2011_743_FAST = new EncryptionParameters(743, 2048, 11, 11, 15, 220, 256, 10, 27, 14, new byte[] {0, 7, 105}, false, true);
    
    public enum TernaryPolynomialType {SIMPLE, PRODUCT};
    
    public int N, q, df, df1, df2, df3;
    int dr, dr1, dr2, dr3, dg, llen, maxMsgLenBytes, db, bufferLenBits, bufferLenTrits, dm0, pkLen, c, minCallsR, minCallsMask;
    byte[] oid;
    boolean sparse;
    boolean fastFp;
    TernaryPolynomialType polyType;
    byte[] reserved;
    
    /**
     * Constructs a parameter set that uses ternary private keys (i.e. </code>polyType=SIMPLE</code>).
     * @param N number of polynomial coefficients
     * @param q modulus
     * @param df number of ones in the private polynomial <code>f</code>
     * @param dm0 minimum acceptable number of -1's, 0's, and 1's in the polynomial <code>m'</code> in the last encryption step
     * @param db number of random bits to prepend to the message
     * @param c a parameter for the Index Generation Function ({@link IndexGenerator})
     * @param minCallsR minimum number of hash calls for the IGF to make
     * @param minCallsMask minimum number of calls to generate the masking polynomial
     * @param oid three bytes that uniquely identify the parameter set
     * @param sparse whether to treat ternary polynomials as sparsely populated ({@link SparseTernaryPolynomial} vs {@link DenseTernaryPolynomial})
     * @param fastFp whether <code>f=1+p*F</code> for a ternary <code>F</code> (true) or <code>f</code> is ternary (false)
     */
    public EncryptionParameters(int N, int q, int df, int dm0, int db, int c, int minCallsR, int minCallsMask, byte[] oid, boolean sparse, boolean fastFp) {
        this.N = N;
        this.q = q;
        this.df = df;
        this.db = db;
        this.dm0 = dm0;
        this.c = c;
        this.minCallsR = minCallsR;
        this.minCallsMask = minCallsMask;
        this.oid = oid;
        this.sparse = sparse;
        this.fastFp = fastFp;
        this.polyType = TernaryPolynomialType.SIMPLE;
        reserved = new byte[16];
        init();
    }

    /**
     * Constructs a parameter set that uses product-form private keys (i.e. </code>polyType=PRODUCT</code>).
     * @param N number of polynomial coefficients
     * @param q modulus
     * @param df1 number of ones in the private polynomial <code>f1</code>
     * @param df2 number of ones in the private polynomial <code>f2</code>
     * @param df3 number of ones in the private polynomial <code>f3</code>
     * @param dm0 minimum acceptable number of -1's, 0's, and 1's in the polynomial <code>m'</code> in the last encryption step
     * @param db number of random bits to prepend to the message
     * @param c a parameter for the Index Generation Function ({@link IndexGenerator})
     * @param minCallsR minimum number of hash calls for the IGF to make
     * @param minCallsMask minimum number of calls to generate the masking polynomial
     * @param oid three bytes that uniquely identify the parameter set
     * @param sparse whether to treat ternary polynomials as sparsely populated ({@link SparseTernaryPolynomial} vs {@link DenseTernaryPolynomial})
     * @param fastFp whether <code>f=1+p*F</code> for a ternary <code>F</code> (true) or <code>f</code> is ternary (false)
     */
    public EncryptionParameters(int N, int q, int df1, int df2, int df3, int dm0, int db, int c, int minCallsR, int minCallsMask, byte[] oid, boolean sparse, boolean fastFp) {
        this.N = N;
        this.q = q;
        this.df1 = df1;
        this.df2 = df2;
        this.df3 = df3;
        this.db = db;
        this.dm0 = dm0;
        this.c = c;
        this.minCallsR = minCallsR;
        this.minCallsMask = minCallsMask;
        this.oid = oid;
        this.sparse = sparse;
        this.fastFp = fastFp;
        this.polyType = TernaryPolynomialType.PRODUCT;
        reserved = new byte[16];
        init();
    }

    private void init() {
        dr = df;
        dr1 = df1;
        dr2 = df2;
        dr3 = df3;
        dg = N / 3;
        llen = 1;   // ceil(log2(maxMsgLenBytes))
        maxMsgLenBytes = N*3/2/8 - llen - db/8;
        bufferLenBits = (N*3/2+7)/8*8;   // one byte more than p1363.1 says
        bufferLenTrits = N - 1;
        pkLen = db / 2;
    }

    /**
     * Reads a parameter set from an input stream.
     * @param is an input stream
     * @throws IOException
     */
    public EncryptionParameters(InputStream is) throws IOException {
        DataInputStream dis = new DataInputStream(is);
        N = dis.readInt();
        q = dis.readInt();
        df = dis.readInt();
        df1 = dis.readInt();
        df2 = dis.readInt();
        df3 = dis.readInt();
        db = dis.readInt();
        dm0 = dis.readInt();
        c = dis.readInt();
        minCallsR = dis.readInt();
        minCallsMask = dis.readInt();
        oid = new byte[3];
        dis.read(oid);
        sparse = dis.readBoolean();
        fastFp = dis.readBoolean();
        polyType = TernaryPolynomialType.values()[dis.read()];
        dis.read(reserved = new byte[16]);
        init();
    }

    public EncryptionParameters clone() {
        if (polyType == TernaryPolynomialType.SIMPLE)
            return new EncryptionParameters(N, q, df, dm0, db, c, minCallsR, minCallsMask, oid, sparse, fastFp);
        else
            return new EncryptionParameters(N, q, df1, df2, df3, dm0, db, c, minCallsR, minCallsMask, oid, sparse, fastFp);
    }
    
    /**
     * Writes the parameter set to an output stream
     * @param os an output stream
     * @throws IOException
     */
    public void writeTo(OutputStream os) throws IOException {
        DataOutputStream dos = new DataOutputStream(os);
        dos.writeInt(N);
        dos.writeInt(q);
        dos.writeInt(df);
        dos.writeInt(df1);
        dos.writeInt(df2);
        dos.writeInt(df3);
        dos.writeInt(db);
        dos.writeInt(dm0);
        dos.writeInt(c);
        dos.writeInt(minCallsR);
        dos.writeInt(minCallsMask);
        dos.write(oid);
        dos.writeBoolean(sparse);
        dos.writeBoolean(fastFp);
        dos.write(polyType.ordinal());
        dos.write(reserved);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + N;
        result = prime * result + bufferLenBits;
        result = prime * result + bufferLenTrits;
        result = prime * result + c;
        result = prime * result + db;
        result = prime * result + df;
        result = prime * result + df1;
        result = prime * result + df2;
        result = prime * result + df3;
        result = prime * result + dg;
        result = prime * result + dm0;
        result = prime * result + dr;
        result = prime * result + dr1;
        result = prime * result + dr2;
        result = prime * result + dr3;
        result = prime * result + (fastFp ? 1231 : 1237);
        result = prime * result + llen;
        result = prime * result + maxMsgLenBytes;
        result = prime * result + minCallsMask;
        result = prime * result + minCallsR;
        result = prime * result + Arrays.hashCode(oid);
        result = prime * result + pkLen;
        result = prime * result + ((polyType == null) ? 0 : polyType.hashCode());
        result = prime * result + q;
        result = prime * result + Arrays.hashCode(reserved);
        result = prime * result + (sparse ? 1231 : 1237);
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        EncryptionParameters other = (EncryptionParameters) obj;
        if (N != other.N)
            return false;
        if (bufferLenBits != other.bufferLenBits)
            return false;
        if (bufferLenTrits != other.bufferLenTrits)
            return false;
        if (c != other.c)
            return false;
        if (db != other.db)
            return false;
        if (df != other.df)
            return false;
        if (df1 != other.df1)
            return false;
        if (df2 != other.df2)
            return false;
        if (df3 != other.df3)
            return false;
        if (dg != other.dg)
            return false;
        if (dm0 != other.dm0)
            return false;
        if (dr != other.dr)
            return false;
        if (dr1 != other.dr1)
            return false;
        if (dr2 != other.dr2)
            return false;
        if (dr3 != other.dr3)
            return false;
        if (fastFp != other.fastFp)
            return false;
        if (llen != other.llen)
            return false;
        if (maxMsgLenBytes != other.maxMsgLenBytes)
            return false;
        if (minCallsMask != other.minCallsMask)
            return false;
        if (minCallsR != other.minCallsR)
            return false;
        if (!Arrays.equals(oid, other.oid))
            return false;
        if (pkLen != other.pkLen)
            return false;
        if (polyType == null) {
            if (other.polyType != null)
                return false;
        } else if (!polyType.equals(other.polyType))
            return false;
        if (q != other.q)
            return false;
        if (!Arrays.equals(reserved, other.reserved))
            return false;
        if (sparse != other.sparse)
            return false;
        return true;
    }
    
    @Override
    public String toString() {
        StringBuilder output = new StringBuilder("EncryptionParameters(N=" + N +" q=" + q);
        if (polyType == TernaryPolynomialType.SIMPLE)
            output.append(" polyType=SIMPLE df=" + df);
        else
            output.append(" polyType=PRODUCT df1=" + df1 + " df2=" + df2 + " df3=" + df3);
        output.append(" dm0=" + dm0 + " db=" + db + " c=" + c + " minCallsR=" + minCallsR + " minCallsMask=" + minCallsMask + " oid=" + Arrays.toString(oid) + " sparse=" + sparse + ")");
        return output.toString();
    }
}