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

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class SignatureParameters {
    public static final SignatureParameters TEST157 = new SignatureParameters(157, 256, 29, 1, BasisType.TRANSPOSE, 0.38, 150, 300, false, false);
    public static final SignatureParameters APR2011_439 = new SignatureParameters(439, 2048, 146, 1, BasisType.TRANSPOSE, 0.165, 400, 1000, false, true);   // gives 128 bits of security
    public static final SignatureParameters APR2011_743 = new SignatureParameters(743, 2048, 248, 1, BasisType.TRANSPOSE, 0.127, 405, 1900, true, false);   // gives 256 bits of security
    
    public enum BasisType {STANDARD, TRANSPOSE};
    
    int N, q, d, B;
    double beta, betaSq, normBound, normBoundSq;
    int keyGenerationDecimalPlaces;
    boolean primeCheck;   // true if N and 2N+1 are prime
    BasisType basisType;
    int bitsF = 6;   // max #bits needed to encode one coefficient of the polynomial F
    boolean sparse;   // whether to treat ternary polynomials as sparsely populated
    
    public SignatureParameters(int N, int q, int d, int B, BasisType basisType, double beta, double normBound, int keyGenerationDecimalPlaces, boolean primeCheck, boolean sparse) {
        this.N = N;
        this.q = q;
        this.d = d;
        this.B = B;
        this.beta = beta;
        this.normBound = normBound;
        this.basisType = basisType;
        this.keyGenerationDecimalPlaces = keyGenerationDecimalPlaces;
        this.primeCheck = primeCheck;
        this.sparse = sparse;
        init();
    }

    private void init() {
        this.betaSq = beta * beta;
        this.normBoundSq = normBound * normBound;
    }

    public SignatureParameters(InputStream is) throws IOException {
        DataInputStream dis = new DataInputStream(is);
        N = dis.readInt();
        q = dis.readInt();
        d = dis.readInt();
        B = dis.readInt();
        basisType = BasisType.values()[dis.readInt()];
        beta = dis.readDouble();
        normBound = dis.readDouble();
        keyGenerationDecimalPlaces = dis.readInt();
        primeCheck = dis.readBoolean();
        sparse = dis.readBoolean();
        bitsF = dis.readInt();
        init();
    }
    
    public void writeTo(OutputStream os) throws IOException {
        DataOutputStream dos = new DataOutputStream(os);
        dos.writeInt(N);
        dos.writeInt(q);
        dos.writeInt(d);
        dos.writeInt(B);
        dos.writeInt(basisType.ordinal());
        dos.writeDouble(beta);
        dos.writeDouble(normBound);
        dos.writeInt(keyGenerationDecimalPlaces);
        dos.writeBoolean(primeCheck);
        dos.writeBoolean(sparse);
        dos.writeInt(bitsF);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + B;
        result = prime * result + N;
        result = prime * result + ((basisType == null) ? 0 : basisType.hashCode());
        long temp;
        temp = Double.doubleToLongBits(beta);
        result = prime * result + (int) (temp ^ (temp >>> 32));
        temp = Double.doubleToLongBits(betaSq);
        result = prime * result + (int) (temp ^ (temp >>> 32));
        result = prime * result + bitsF;
        result = prime * result + d;
        result = prime * result + keyGenerationDecimalPlaces;
        temp = Double.doubleToLongBits(normBound);
        result = prime * result + (int) (temp ^ (temp >>> 32));
        temp = Double.doubleToLongBits(normBoundSq);
        result = prime * result + (int) (temp ^ (temp >>> 32));
        result = prime * result + (primeCheck ? 1231 : 1237);
        result = prime * result + q;
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
        SignatureParameters other = (SignatureParameters) obj;
        if (B != other.B)
            return false;
        if (N != other.N)
            return false;
        if (basisType == null) {
            if (other.basisType != null)
                return false;
        } else if (!basisType.equals(other.basisType))
            return false;
        if (Double.doubleToLongBits(beta) != Double.doubleToLongBits(other.beta))
            return false;
        if (Double.doubleToLongBits(betaSq) != Double.doubleToLongBits(other.betaSq))
            return false;
        if (bitsF != other.bitsF)
            return false;
        if (d != other.d)
            return false;
        if (keyGenerationDecimalPlaces != other.keyGenerationDecimalPlaces)
            return false;
        if (Double.doubleToLongBits(normBound) != Double.doubleToLongBits(other.normBound))
            return false;
        if (Double.doubleToLongBits(normBoundSq) != Double.doubleToLongBits(other.normBoundSq))
            return false;
        if (primeCheck != other.primeCheck)
            return false;
        if (q != other.q)
            return false;
        if (sparse != other.sparse)
            return false;
        return true;
    }
}