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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import net.sf.ntru.exception.NtruException;
import net.sf.ntru.polynomial.DenseTernaryPolynomial;
import net.sf.ntru.polynomial.IntegerPolynomial;
import net.sf.ntru.polynomial.Polynomial;
import net.sf.ntru.polynomial.ProductFormPolynomial;
import net.sf.ntru.polynomial.SparseTernaryPolynomial;
import net.sf.ntru.sign.NtruSign.FGBasis;
import net.sf.ntru.sign.SignatureParameters.BasisType;
import net.sf.ntru.sign.SignatureParameters.TernaryPolynomialType;

/**
 * A NtruSign private key comprises one or more {@link SignaturePrivateKey.Basis} of three polynomials each,
 * except the zeroth basis for which <code>h</code> is undefined.
 */
public class SignaturePrivateKey {
    private List<Basis> bases;
    
    /**
     * Constructs a new private key from a byte array
     * @param b an encoded private key
     * @param params the NtruSign parameters to use
     */
    public SignaturePrivateKey(byte[] b, SignatureParameters params) {
        bases = new ArrayList<Basis>();
        ByteArrayInputStream is = new ByteArrayInputStream(b);
        for (int i=0; i<=params.B; i++)
            try {
                add(new Basis(is, params, i!=0));
            } catch (IOException e) {
                throw new NtruException(e);
            }
    }
    
    /**
     * Constructs a new private key from an input stream
     * @param is an input stream
     * @param params the NtruSign parameters to use
     */
    public SignaturePrivateKey(InputStream is, SignatureParameters params) throws IOException {
        bases = new ArrayList<Basis>();
        for (int i=0; i<=params.B; i++)
            // include a public key h[i] in all bases except for the first one
            add(new Basis(is, params, i!=0));
    }
    
    /**
     * Constructs an empty private key
     */
    SignaturePrivateKey() {
        bases = new ArrayList<Basis>();
    }
    
    /**
     * Adds a basis to the key.
     * @param b a NtruSign basis
     */
    void add(Basis b) {
        bases.add(b);
    }
    
    /**
     * Returns the <code>i</code>-th basis
     * @param <code>i</code> the index
     * @return the basis at index <code>i</code>
     */
    Basis getBasis(int i) {
        return bases.get(i);
    }
    
    /**
     * Converts the key to a byte array
     * @return the encoded key
     */
   public byte[] getEncoded() {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        for (int i=0; i<bases.size(); i++)
            try {
                // all bases except for the first one contain a public key
                bases.get(i).encode(os, i!=0);
            } catch (IOException e) {
                throw new NtruException(e);
            }
        return os.toByteArray();
    }
    
   /**
    * Writes the key to an output stream
    * @param os an output stream
    * @throws IOException
    */
    public void writeTo(OutputStream os) throws IOException {
        os.write(getEncoded());
    }
    
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((bases == null) ? 0 : bases.hashCode());
        for (Basis basis: bases)
            result += basis.hashCode();
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
        SignaturePrivateKey other = (SignaturePrivateKey) obj;
        if (bases == null) {
            if (other.bases != null)
                return false;
        }
        if (bases.size() != other.bases.size())
            return false;
        for (int i=0; i<bases.size(); i++) {
            Basis basis1 = bases.get(i);
            Basis basis2 = other.bases.get(i);
            if (!basis1.f.equals(basis2.f))
                return false;
            if (!basis1.fPrime.equals(basis2.fPrime))
                return false;
            if (i!=0 && !basis1.h.equals(basis2.h))   // don't compare h for the 0th basis
                return false;
            if (!basis1.params.equals(basis2.params))
                return false;
        }
        return true;
    }

    /** A NtruSign basis. Contains three polynomials <code>f, f', h</code>. */
    static class Basis {
        Polynomial f;
        Polynomial fPrime;
        IntegerPolynomial h;
        SignatureParameters params;
        
        /**
         * Constructs a new basis from polynomials <code>f, f', h</code>.
         * @param f
         * @param fPrime
         * @param h
         * @param params NtruSign parameters
         */
        Basis(Polynomial f, Polynomial fPrime, IntegerPolynomial h, SignatureParameters params) {
            this.f = f;
            this.fPrime = fPrime;
            this.h = h;
            this.params = params;
        }
        
        /**
         * Reads a basis from an input stream and constructs a new basis.
         * @param is an input stream
         * @param params NtruSign parameters
         * @param include_h whether to read the polynomial <code>h</code> (<code>true</code>) or only <code>f</code> and <code>f'</code> (<code>false</code>)
         */
        Basis(InputStream is, SignatureParameters params, boolean include_h) throws IOException {
            int N = params.N;
            int q = params.q;
            int d1 = params.d1;
            int d2 = params.d2;
            int d3 = params.d3;
            boolean sparse = params.sparse;
            this.params = params;
            
            if (params.polyType == TernaryPolynomialType.PRODUCT)
                f = ProductFormPolynomial.fromBinary(is, N, d1, d2, d3+1, d3);
            else {
                IntegerPolynomial fInt = IntegerPolynomial.fromBinary3Tight(is, N);
                f = sparse ? new SparseTernaryPolynomial(fInt) : new DenseTernaryPolynomial(fInt);
            }
            
            if (params.basisType == BasisType.STANDARD) {
                IntegerPolynomial fPrimeInt = IntegerPolynomial.fromBinary(is, N, q);
                for (int i=0; i<fPrimeInt.coeffs.length; i++)
                    fPrimeInt.coeffs[i] -= q/2;
                fPrime = fPrimeInt;
            }
            else
                if (params.polyType == TernaryPolynomialType.PRODUCT)
                    fPrime = ProductFormPolynomial.fromBinary(is, N, d1, d2, d3+1, d3);
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
            int q = params.q;
            
            os.write(getEncoded(f));
            if (params.basisType == BasisType.STANDARD) {
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
            int N = params.N;
            int q = params.q;
            
            if (f.toIntegerPolynomial().coeffs.length != N)
                return false;
            if (fPrime.toIntegerPolynomial().coeffs.length != N)
                return false;
            
            if (h.coeffs.length!=N || !h.isReduced(q))
                return false;
            
            // determine F, G, g from f, fPrime, h using the eqn. fG-Fg=q
            Polynomial FPoly = params.basisType==BasisType.STANDARD ? fPrime : f.mult(h, q);
            IntegerPolynomial F = FPoly.toIntegerPolynomial();
            IntegerPolynomial fq = f.toIntegerPolynomial().invertFq(q);
            Polynomial g = params.basisType==BasisType.STANDARD ? f.mult(h, q) : fPrime;
            IntegerPolynomial G = g.mult(F);
            G.coeffs[0] -= q;
            G = G.mult(fq, q);
            G.modCenter(q);
            
            // check norms of F and G
            if (!new FGBasis(f, fPrime, h, F, G, params).isNormOk())
                return false;
            // check norms of f and g
            int factor = N / 24;
            if (f.toIntegerPolynomial().centeredNormSq(q)*factor >= F.centeredNormSq(q))
                return false;
            if (g.toIntegerPolynomial().centeredNormSq(q)*factor >= G.centeredNormSq(q))
                return false;
            
            // check ternarity
            if (params.polyType == TernaryPolynomialType.SIMPLE) {
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
            result = prime * result + ((f == null) ? 0 : f.hashCode());
            result = prime * result + ((fPrime == null) ? 0 : fPrime.hashCode());
            result = prime * result + ((h == null) ? 0 : h.hashCode());
            result = prime * result + ((params == null) ? 0 : params.hashCode());
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
            if (params == null) {
                if (other.params != null)
                    return false;
            } else if (!params.equals(other.params))
                return false;
            return true;
        }
    }
}