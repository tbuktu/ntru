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

public class SignatureParameters {
    public static final SignatureParameters TEST157 = new SignatureParameters(157, 256, 29, 1, BasisType.TRANSPOSE, 0.38407, 150.02, false);
    public static final SignatureParameters MAR2011_439 = new SignatureParameters(439, 2048, 146, 1, BasisType.TRANSPOSE, 0.16533, 400, false);   // gives 128 bits of security
    public static final SignatureParameters MAR2011_743 = new SignatureParameters(743, 2048, 248, 1, BasisType.TRANSPOSE, 0.12709, 405, true);   // gives 256 bits of security
    
    public enum BasisType {STANDARD, TRANSPOSE};
    
    int N, q, d, B;
    double betaSq, normBoundSq;
    boolean primeCheck;   // true if N and 2N+1 are prime
    BasisType basisType;
    int bitsF = 6;   // max #bits needed to encode one coefficient of the polynomial F
    
    public SignatureParameters(int N, int q, int d, int B, BasisType basisType, double beta, double normBound, boolean primeCheck) {
        this.N = N;
        this.q = q;
        this.d = d;
        this.B = B;
        this.basisType = basisType;
        this.betaSq = beta * beta;
        this.normBoundSq = normBound * normBound;
    }
}