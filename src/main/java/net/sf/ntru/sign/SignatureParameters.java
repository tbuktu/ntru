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

package net.sf.ntru.sign;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.text.DecimalFormat;

import net.sf.ntru.polynomial.DenseTernaryPolynomial;
import net.sf.ntru.polynomial.SparseTernaryPolynomial;

/**
 * A set of parameters for NtruSign. Several predefined parameter sets are available and new ones can be created as well.
 */
public class SignatureParameters implements Cloneable {
    /** Gives 128 bits of security */
    public static final SignatureParameters APR2011_439 = new SignatureParameters(439, 2048, 146, 1, BasisType.TRANSPOSE, 0.165f, 400, 280, false, true, KeyGenAlg.RESULTANT, "SHA-256");
    
    /** Like <code>APR2011_439</code>, this parameter set gives 128 bits of security but uses product-form polynomials */
    public static final SignatureParameters APR2011_439_PROD = new SignatureParameters(439, 2048, 9, 8, 5, 1, BasisType.TRANSPOSE, 0.165f, 400, 280, false, true, KeyGenAlg.RESULTANT, "SHA-256");
    
    /** Gives 256 bits of security */
    public static final SignatureParameters APR2011_743 = new SignatureParameters(743, 2048, 248, 1, BasisType.TRANSPOSE, 0.127f, 405, 360, true, false, KeyGenAlg.RESULTANT, "SHA-512");
    
    /** Like <code>APR2011_439</code>, this parameter set gives 256 bits of security but uses product-form polynomials */
    public static final SignatureParameters APR2011_743_PROD = new SignatureParameters(743, 2048, 11, 11, 15, 1, BasisType.TRANSPOSE, 0.127f, 405, 360, true, false, KeyGenAlg.RESULTANT, "SHA-512");
    
    /** Generates key pairs quickly. Use for testing only. */
    public static final SignatureParameters TEST157 = new SignatureParameters(157, 256, 29, 1, BasisType.TRANSPOSE, 0.38f, 200, 80, false, false, KeyGenAlg.RESULTANT, "SHA-256");
    /** Generates key pairs quickly. Use for testing only. */
    public static final SignatureParameters TEST157_PROD = new SignatureParameters(157, 256, 5, 5, 8, 1, BasisType.TRANSPOSE, 0.38f, 200, 80, false, false, KeyGenAlg.RESULTANT, "SHA-256");
    
    public enum BasisType {STANDARD, TRANSPOSE};
    public enum KeyGenAlg {RESULTANT, FLOAT};
    public enum TernaryPolynomialType {SIMPLE, PRODUCT};
    
    public int N;
    int q;
    public int d, d1, d2, d3, B;
    float beta, betaSq, normBound, normBoundSq;
    int signFailTolerance = 100;
    float keyNormBound, keyNormBoundSq;
    boolean primeCheck;   // true if N and 2N+1 are prime
    BasisType basisType;
    int bitsF = 6;   // max #bits needed to encode one coefficient of the polynomial F
    boolean sparse;   // whether to treat ternary polynomials as sparsely populated
    KeyGenAlg keyGenAlg;
    String hashAlg;
    TernaryPolynomialType polyType;
    
    /**
     * Constructs a parameter set that uses ternary private keys (i.e. </code>polyType=SIMPLE</code>).
     * @param N            number of polynomial coefficients
     * @param q            modulus
     * @param d            number of -1's in the private polynomials <code>f</code> and <code>g</code>
     * @param B            number of perturbations
     * @param basisType    whether to use the standard or transpose lattice
     * @param beta         balancing factor for the transpose lattice
     * @param normBound    maximum norm for valid signatures
     * @param keyNormBound maximum norm for the polynomials <code>F</code> and <code>G</code>
     * @param primeCheck   whether <code>2N+1</code> is prime
     * @param sparse       whether to treat ternary polynomials as sparsely populated ({@link SparseTernaryPolynomial} vs {@link DenseTernaryPolynomial})
     * @param keyGenAlg    <code>RESULTANT</code> produces better bases, <code>FLOAT</code> is slightly faster. <code>RESULTANT</code> follows the EESS standard while <code>FLOAT</code> is described in Hoffstein et al: An Introduction to Mathematical Cryptography.
     * @param hashAlg      a valid identifier for a <code>java.security.MessageDigest</code> instance such as <code>SHA-256</code>. The <code>MessageDigest</code> must support the <code>getDigestLength()</code> method.
     */
    public SignatureParameters(int N, int q, int d, int B, BasisType basisType, float beta, float normBound, float keyNormBound, boolean primeCheck, boolean sparse, KeyGenAlg keyGenAlg, String hashAlg) {
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
        this.hashAlg = hashAlg;
        polyType = TernaryPolynomialType.SIMPLE;
        init();
    }

    /**
     * Constructs a parameter set that uses product-form private keys (i.e. </code>polyType=PRODUCT</code>).
     * @param N            number of polynomial coefficients
     * @param q            modulus
     * @param d1           number of -1's in the private polynomials <code>f</code> and <code>g</code>
     * @param d2           number of -1's in the private polynomials <code>f</code> and <code>g</code>
     * @param d3           number of -1's in the private polynomials <code>f</code> and <code>g</code>
     * @param B            number of perturbations
     * @param basisType    whether to use the standard or transpose lattice
     * @param beta         balancing factor for the transpose lattice
     * @param normBound    maximum norm for valid signatures
     * @param keyNormBound maximum norm for the polynomials <code>F</code> and <code>G</code>
     * @param primeCheck   whether <code>2N+1</code> is prime
     * @param sparse       whether to treat ternary polynomials as sparsely populated ({@link SparseTernaryPolynomial} vs {@link DenseTernaryPolynomial})
     * @param keyGenAlg    <code>RESULTANT</code> produces better bases, <code>FLOAT</code> is slightly faster. <code>RESULTANT</code> follows the EESS standard while <code>FLOAT</code> is described in Hoffstein et al: An Introduction to Mathematical Cryptography.
     * @param hashAlg      a valid identifier for a <code>java.security.MessageDigest</code> instance such as <code>SHA-256</code>. The <code>MessageDigest</code> must support the <code>getDigestLength()</code> method.
     */
    public SignatureParameters(int N, int q, int d1, int d2, int d3, int B, BasisType basisType, float beta, float normBound, float keyNormBound, boolean primeCheck, boolean sparse, KeyGenAlg keyGenAlg, String hashAlg) {
        this.N = N;
        this.q = q;
        this.d1 = d1;
        this.d2 = d2;
        this.d3 = d3;
        this.B = B;
        this.basisType = basisType;
        this.beta = beta;
        this.normBound = normBound;
        this.keyNormBound = keyNormBound;
        this.primeCheck = primeCheck;
        this.sparse = sparse;
        this.keyGenAlg = keyGenAlg;
        this.hashAlg = hashAlg;
        polyType = TernaryPolynomialType.PRODUCT;
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
        d1 = dis.readInt();
        d2 = dis.readInt();
        d3 = dis.readInt();
        B = dis.readInt();
        basisType = BasisType.values()[dis.readInt()];
        beta = dis.readFloat();
        normBound = dis.readFloat();
        keyNormBound = dis.readFloat();
        signFailTolerance = dis.readInt();
        primeCheck = dis.readBoolean();
        sparse = dis.readBoolean();
        bitsF = dis.readInt();
        keyGenAlg = KeyGenAlg.values()[dis.read()];
        hashAlg = dis.readUTF();
        polyType = TernaryPolynomialType.values()[dis.read()];
        init();
    }
    
    /**
     * Returns the length of a signature made with this parameter set.<br/>
     * The length does not depend on the message size.
     * @return the length in bytes
     */
    public int getOutputLength() {
        int logq = 32 - Integer.numberOfLeadingZeros(q - 1);   // ceil(log q)
        int polyLen = (N*logq+7) / 8;   // length of a polynomial in bytes
        return polyLen + 4;   // add 4 for the retry count
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
        dos.writeInt(d1);
        dos.writeInt(d2);
        dos.writeInt(d3);
        dos.writeInt(B);
        dos.writeInt(basisType.ordinal());
        dos.writeFloat(beta);
        dos.writeFloat(normBound);
        dos.writeFloat(keyNormBound);
        dos.writeInt(signFailTolerance);
        dos.writeBoolean(primeCheck);
        dos.writeBoolean(sparse);
        dos.writeInt(bitsF);
        dos.write(keyGenAlg.ordinal());
        dos.writeUTF(hashAlg);
        dos.write(polyType.ordinal());
    }

    @Override
    public SignatureParameters clone() {
        if (polyType == TernaryPolynomialType.SIMPLE)
            return new SignatureParameters(N, q, d, B, basisType, beta, normBound, keyNormBound, primeCheck, sparse, keyGenAlg, hashAlg);
        else
            return new SignatureParameters(N, q, d1, d2, d3, B, basisType, beta, normBound, keyNormBound, primeCheck, sparse, keyGenAlg, hashAlg);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + B;
        result = prime * result + N;
        result = prime * result + ((basisType == null) ? 0 : basisType.hashCode());
        long temp;
        temp = Float.floatToIntBits(beta);
        result = prime * result + (int) (temp ^ (temp >>> 32));
        temp = Float.floatToIntBits(betaSq);
        result = prime * result + (int) (temp ^ (temp >>> 32));
        result = prime * result + bitsF;
        result = prime * result + d;
        result = prime * result + d1;
        result = prime * result + d2;
        result = prime * result + d3;
        result = prime * result + ((hashAlg == null) ? 0 : hashAlg.hashCode());
        result = prime * result + ((keyGenAlg == null) ? 0 : keyGenAlg.hashCode());
        temp = Float.floatToIntBits(keyNormBound);
        result = prime * result + (int) (temp ^ (temp >>> 32));
        temp = Float.floatToIntBits(keyNormBoundSq);
        result = prime * result + (int) (temp ^ (temp >>> 32));
        temp = Float.floatToIntBits(normBound);
        result = prime * result + (int) (temp ^ (temp >>> 32));
        temp = Float.floatToIntBits(normBoundSq);
        result = prime * result + (int) (temp ^ (temp >>> 32));
        result = prime * result + ((polyType == null) ? 0 : polyType.hashCode());
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
        if (!(obj instanceof SignatureParameters))
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
        if (Float.floatToIntBits(beta) != Float.floatToIntBits(other.beta))
            return false;
        if (Float.floatToIntBits(betaSq) != Float.floatToIntBits(other.betaSq))
            return false;
        if (bitsF != other.bitsF)
            return false;
        if (d != other.d)
            return false;
        if (d1 != other.d1)
            return false;
        if (d2 != other.d2)
            return false;
        if (d3 != other.d3)
            return false;
        if (hashAlg == null) {
            if (other.hashAlg != null)
                return false;
        } else if (!hashAlg.equals(other.hashAlg))
            return false;
        if (keyGenAlg == null) {
            if (other.keyGenAlg != null)
                return false;
        } else if (!keyGenAlg.equals(other.keyGenAlg))
            return false;
        if (Float.floatToIntBits(keyNormBound) != Float.floatToIntBits(other.keyNormBound))
            return false;
        if (Float.floatToIntBits(keyNormBoundSq) != Float.floatToIntBits(other.keyNormBoundSq))
            return false;
        if (Float.floatToIntBits(normBound) != Float.floatToIntBits(other.normBound))
            return false;
        if (Float.floatToIntBits(normBoundSq) != Float.floatToIntBits(other.normBoundSq))
            return false;
        if (polyType == null) {
            if (other.polyType != null)
                return false;
        } else if (!polyType.equals(other.polyType))
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
        
        StringBuilder output = new StringBuilder("SignatureParameters(N=" + N + " q=" + q);
        if (polyType == TernaryPolynomialType.SIMPLE)
            output.append(" polyType=SIMPLE d=" + d);
        else
            output.append(" polyType=PRODUCT d1=" + d1 + " d2=" + d2 + " d3=" + d3);
        output.append(" B=" + B + " basisType=" + basisType + " beta=" + format.format(beta) +
                " normBound=" + format.format(normBound) + " keyNormBound=" + format.format(keyNormBound) +
                " prime=" + primeCheck + " sparse=" + sparse + " keyGenAlg=" + keyGenAlg + " hashAlg=" + hashAlg + ")");
        return output.toString();
    }
}