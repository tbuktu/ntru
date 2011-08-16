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

package net.sf.ntru.sign;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.text.DecimalFormat;
import java.util.Arrays;

import net.sf.ntru.polynomial.DenseTernaryPolynomial;
import net.sf.ntru.polynomial.SparseTernaryPolynomial;

/**
 * A set of parameters for NtruSign. Several predefined parameter sets are available and new ones can be created as well.
 */
public class SignatureParameters implements Cloneable {
    /** Gives 128 bits of security */
    public static final SignatureParameters APR2011_439 = new SignatureParameters(439, 2048, 146, 1, BasisType.TRANSPOSE, 0.165, 400, 280, false, true, KeyGenAlg.RESULTANT);
    
    /** Same as APR2011_439 but uses KeyGenAlg.FLOAT */
    public static final SignatureParameters APR2011_439_FAST = APR2011_439.clone().setKeyGenAlgorithm(KeyGenAlg.FLOAT);
    
    /** Gives 256 bits of security */
    public static final SignatureParameters APR2011_743 = new SignatureParameters(743, 2048, 248, 1, BasisType.TRANSPOSE, 0.127, 405, 360, true, false, KeyGenAlg.RESULTANT);
    
    /** Same as APR2011_743 but uses KeyGenAlg.FLOAT */
    public static final SignatureParameters APR2011_743_FAST = APR2011_743.clone().setKeyGenAlgorithm(KeyGenAlg.FLOAT);
    
    /** Generates key pairs quickly. Use for testing only. */
    public static final SignatureParameters TEST157 = new SignatureParameters(157, 256, 29, 1, BasisType.TRANSPOSE, 0.38, 200, 80, false, false, KeyGenAlg.RESULTANT);
    
    public enum BasisType {STANDARD, TRANSPOSE};
    public enum KeyGenAlg {RESULTANT, FLOAT};
    
    public int N;
    int q;
    public int d, B;
    double beta, betaSq, normBound, normBoundSq;
    int signFailTolerance = 100;
    double keyNormBound, keyNormBoundSq;
    boolean primeCheck;   // true if N and 2N+1 are prime
    BasisType basisType;
    int bitsF = 6;   // max #bits needed to encode one coefficient of the polynomial F
    boolean sparse;   // whether to treat ternary polynomials as sparsely populated
    KeyGenAlg keyGenAlg;
    
    /**
     * Constructs a new set of signature parameters.
     * @param N number of polynomial coefficients
     * @param q modulus
     * @param d number of -1's in the private polynomials <code>f</code> and <code>g</code>
     * @param B number of perturbations
     * @param basisType whether to use the standard or transpose lattice
     * @param beta balancing factor for the transpose lattice
     * @param normBound maximum norm for valid signatures
     * @param keyNormBound maximum norm for the ploynomials <code>F</code> and <code>G</code>
     * @param primeCheck whether <code>2N+1</code> is prime
     * @param sparse whether to treat ternary polynomials as sparsely populated ({@link SparseTernaryPolynomial} vs {@link DenseTernaryPolynomial})
     * @param keyGenAlg <code>RESULTANT</code> produces better bases, <code>FLOAT</code> is faster
     */
    public SignatureParameters(int N, int q, int d, int B, BasisType basisType, double beta, double normBound, double keyNormBound, boolean primeCheck, boolean sparse, KeyGenAlg keyGenAlg) {
        this.N = N;
        this.q = q;
        this.d = d;
        this.B = B;
        this.basisType = basisType;
        this.beta = beta;
        this.normBound = normBound;
        this.keyNormBound = keyNormBound;
        this.primeCheck = primeCheck;
        this.sparse = sparse;
        this.keyGenAlg = keyGenAlg;
        init();
    }

    private void init() {
        betaSq = beta * beta;
        normBoundSq = normBound * normBound;
        keyNormBoundSq = keyNormBound * keyNormBound;
    }

    /**
     * Reads a parameter set from an input stream.
     * @param is an input stream
     * @throws IOException
     */
    public SignatureParameters(InputStream is) throws IOException {
        DataInputStream dis = new DataInputStream(is);
        N = dis.readInt();
        q = dis.readInt();
        d = dis.readInt();
        B = dis.readInt();
        basisType = BasisType.values()[dis.readInt()];
        beta = dis.readDouble();
        normBound = dis.readDouble();
        keyNormBound = dis.readDouble();
        signFailTolerance = dis.readInt();
        primeCheck = dis.readBoolean();
        sparse = dis.readBoolean();
        bitsF = dis.readInt();
        keyGenAlg = KeyGenAlg.values()[dis.read()];
        init();
    }
    
    /**
     * Sets the algorithm to use when generating a key pair. Modifies this object and returns it.
     * @param alg KeyGenAlg.FLOAT or KeyGenAlg.RESULTANT
     * @return the modified parameters
     */
    public SignatureParameters setKeyGenAlgorithm(KeyGenAlg alg) {
        keyGenAlg = alg;
        return this;
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
        dos.writeInt(d);
        dos.writeInt(B);
        dos.writeInt(basisType.ordinal());
        dos.writeDouble(beta);
        dos.writeDouble(normBound);
        dos.writeDouble(keyNormBound);
        dos.writeInt(signFailTolerance);
        dos.writeBoolean(primeCheck);
        dos.writeBoolean(sparse);
        dos.writeInt(bitsF);
        dos.write(keyGenAlg.ordinal());
    }

    @Override
    public SignatureParameters clone() {
        return new SignatureParameters(N, q, d, B, basisType, beta, normBound, keyNormBound, primeCheck, sparse, keyGenAlg);
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
        result = prime * result + ((keyGenAlg == null) ? 0 : keyGenAlg.hashCode());
        temp = Double.doubleToLongBits(keyNormBound);
        result = prime * result + (int) (temp ^ (temp >>> 32));
        temp = Double.doubleToLongBits(keyNormBoundSq);
        result = prime * result + (int) (temp ^ (temp >>> 32));
        temp = Double.doubleToLongBits(normBound);
        result = prime * result + (int) (temp ^ (temp >>> 32));
        temp = Double.doubleToLongBits(normBoundSq);
        result = prime * result + (int) (temp ^ (temp >>> 32));
        result = prime * result + (primeCheck ? 1231 : 1237);
        result = prime * result + q;
        result = prime * result + signFailTolerance;
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
        if (keyGenAlg == null) {
            if (other.keyGenAlg != null)
                return false;
        } else if (!keyGenAlg.equals(other.keyGenAlg))
            return false;
        if (Double.doubleToLongBits(keyNormBound) != Double.doubleToLongBits(other.keyNormBound))
            return false;
        if (Double.doubleToLongBits(keyNormBoundSq) != Double.doubleToLongBits(other.keyNormBoundSq))
            return false;
        if (Double.doubleToLongBits(normBound) != Double.doubleToLongBits(other.normBound))
            return false;
        if (Double.doubleToLongBits(normBoundSq) != Double.doubleToLongBits(other.normBoundSq))
            return false;
        if (primeCheck != other.primeCheck)
            return false;
        if (q != other.q)
            return false;
        if (signFailTolerance != other.signFailTolerance)
            return false;
        if (sparse != other.sparse)
            return false;
        return true;
    }
    
    @Override
    public String toString() {
        DecimalFormat format = new DecimalFormat("0.00");
        return "SignatureParameters(N=" + N + " q=" + q + " d=" + d + " B=" + B + " basisType=" + basisType + " beta=" + format.format(beta) +
                " normBound=" + format.format(normBound) + " keyNormBound=" + format.format(keyNormBound) +
                " prime=" + primeCheck + " sparse=" + sparse + " keyGenAlg=" + keyGenAlg + ")";
    }
}