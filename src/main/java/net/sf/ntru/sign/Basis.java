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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import net.sf.ntru.polynomial.DenseTernaryPolynomial;
import net.sf.ntru.polynomial.IntegerPolynomial;
import net.sf.ntru.polynomial.Polynomial;
import net.sf.ntru.polynomial.ProductFormPolynomial;
import net.sf.ntru.polynomial.SparseTernaryPolynomial;
import net.sf.ntru.sign.NtruSign.FGBasis;
import net.sf.ntru.sign.SignatureParameters.BasisType;
import net.sf.ntru.sign.SignatureParameters.TernaryPolynomialType;

/** A NtruSign basis. Contains three polynomials <code>f, f', h</code>. */
class Basis {
    Polynomial f;
    Polynomial fPrime;
    IntegerPolynomial h;
    int N;
    int q;
    private TernaryPolynomialType polyType;
    private BasisType basisType;
    private double keyNormBoundSq;
    
    /**
     * Constructs a new basis from polynomials <code>f, f', h</code>.
     * @param f
     * @param fPrime
     * @param h
     * @param params NtruSign parameters
     */
    Basis(Polynomial f, Polynomial fPrime, IntegerPolynomial h, int q, TernaryPolynomialType polyType, BasisType basisType, double keyNormBoundSq) {
        this.f = f;
        this.fPrime = fPrime;
        this.h = h;
        this.N = h.coeffs.length;
        this.q = q;
        this.polyType = polyType;
        this.basisType = basisType;
        this.keyNormBoundSq = keyNormBoundSq;
    }
    
    /**
     * Reads a basis from an input stream and constructs a new basis.
     * @param is an input stream
     * @param params NtruSign parameters
     * @param include_h whether to read the polynomial <code>h</code> (<code>true</code>) or only <code>f</code> and <code>f'</code> (<code>false</code>)
     * @throws IOException
     */
    Basis(InputStream is, int N, int q, boolean sparse, TernaryPolynomialType polyType, BasisType basisType, double keyNormBoundSq, boolean include_h) throws IOException {
        this.N = N;
        this.q = q;
        this.polyType = polyType;
        this.basisType = basisType;
        this.keyNormBoundSq = keyNormBoundSq;

        if (polyType == TernaryPolynomialType.PRODUCT)
            f = ProductFormPolynomial.fromBinary(is, N);
        else {
            IntegerPolynomial fInt = IntegerPolynomial.fromBinary3Tight(is, N);
            f = sparse ? new SparseTernaryPolynomial(fInt) : new DenseTernaryPolynomial(fInt);
        }
        
        if (basisType == BasisType.STANDARD) {
            IntegerPolynomial fPrimeInt = IntegerPolynomial.fromBinary(is, N, q);
            for (int i=0; i<fPrimeInt.coeffs.length; i++)
                fPrimeInt.coeffs[i] -= q/2;
            fPrime = fPrimeInt;
        }
        else
            if (polyType == TernaryPolynomialType.PRODUCT)
                fPrime = ProductFormPolynomial.fromBinary(is, N);
            else
                fPrime = IntegerPolynomial.fromBinary3Tight(is, N);
        
        if (include_h)
            h = IntegerPolynomial.fromBinary(is, N, q);
    }
    
    /**
     * Writes the basis to an output stream
     * @param os an output stream
     * @param include_h whether to write the polynomial <code>h</code> (<code>true</code>) or only <code>f</code> and <code>f'</code> (<code>false</code>)
     * @throws IOException
     */
    void encode(OutputStream os, boolean include_h) throws IOException {
        os.write(getEncoded(f));
        if (basisType == BasisType.STANDARD) {
            IntegerPolynomial fPrimeInt = fPrime.toIntegerPolynomial();
            for (int i=0; i<fPrimeInt.coeffs.length; i++)
                fPrimeInt.coeffs[i] += q/2;
            os.write(fPrimeInt.toBinary(q));
        }
        else
            os.write(getEncoded(fPrime));
        if (include_h)
            os.write(h.toBinary(q));
    }

    private byte[] getEncoded(Polynomial p) {
        if (p instanceof ProductFormPolynomial)
            return ((ProductFormPolynomial)p).toBinary();
        else
            return p.toIntegerPolynomial().toBinary3Tight();
    }
    
    /**
     * Tests if the basis is valid.
     * @param h the polynomial h (either from the public key or from this basis)
     * @return <code>true</code> if the basis is valid, <code>false</code> otherwise
     */
    boolean isValid(IntegerPolynomial h) {
        if (f.toIntegerPolynomial().coeffs.length != N)
            return false;
        if (fPrime.toIntegerPolynomial().coeffs.length != N)
            return false;
        
        if (h.coeffs.length!=N || !h.isReduced(q))
            return false;
        
        // determine F, G, g from f, fPrime, h using the eqn. fG-Fg=q
        Polynomial FPoly = basisType==BasisType.STANDARD ? fPrime : f.mult(h, q);
        IntegerPolynomial F = FPoly.toIntegerPolynomial();
        IntegerPolynomial fq = f.toIntegerPolynomial().invertFq(q);
        Polynomial g = basisType==BasisType.STANDARD ? f.mult(h, q) : fPrime;
        IntegerPolynomial G = g.mult(F);
        G.coeffs[0] -= q;
        G = G.mult(fq, q);
        G.modCenter(q);
        
        // check norms of F and G
        if (!new FGBasis(f, fPrime, h, F, G, q, polyType, basisType, keyNormBoundSq).isNormOk())
            return false;
        // check norms of f and g
        int factor = N / 24;
        if (f.toIntegerPolynomial().centeredNormSq(q)*factor >= F.centeredNormSq(q))
            return false;
        if (g.toIntegerPolynomial().centeredNormSq(q)*factor >= G.centeredNormSq(q))
            return false;
        
        // check ternarity
        if (polyType == TernaryPolynomialType.SIMPLE) {
            if (!f.toIntegerPolynomial().isTernary())
                return false;
            if (!g.toIntegerPolynomial().isTernary())
                return false;
        }
        else {
            if (!(f instanceof ProductFormPolynomial))
                return false;
            if (!(g instanceof ProductFormPolynomial))
                return false;
        }
        
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + N;
        result = prime * result
                + ((basisType == null) ? 0 : basisType.hashCode());
        result = prime * result + ((f == null) ? 0 : f.hashCode());
        result = prime * result
                + ((fPrime == null) ? 0 : fPrime.hashCode());
        result = prime * result + ((h == null) ? 0 : h.hashCode());
        long temp;
        temp = Double.doubleToLongBits(keyNormBoundSq);
        result = prime * result + (int) (temp ^ (temp >>> 32));
        result = prime * result
                + ((polyType == null) ? 0 : polyType.hashCode());
        result = prime * result + q;
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (!(obj instanceof Basis))
            return false;
        Basis other = (Basis) obj;
        if (N != other.N)
            return false;
        if (basisType != other.basisType)
            return false;
        if (f == null) {
            if (other.f != null)
                return false;
        } else if (!f.equals(other.f))
            return false;
        if (fPrime == null) {
            if (other.fPrime != null)
                return false;
        } else if (!fPrime.equals(other.fPrime))
            return false;
        if (h == null) {
            if (other.h != null)
                return false;
        } else if (!h.equals(other.h))
            return false;
        if (Double.doubleToLongBits(keyNormBoundSq) != Double
                .doubleToLongBits(other.keyNormBoundSq))
            return false;
        if (polyType != other.polyType)
            return false;
        if (q != other.q)
            return false;
        return true;
    }
}