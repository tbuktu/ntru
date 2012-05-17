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
import java.io.DataInputStream;
import java.io.DataOutputStream;
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
    int N;
    int q;
    private boolean sparse;
    private TernaryPolynomialType polyType;
    private BasisType basisType;
    private float keyNormBoundSq;
    private List<Basis> bases;
    
    /**
     * Constructs a new private key from a byte array
     * @param b an encoded private key
     * @param params the NtruSign parameters to use
     */
    public SignaturePrivateKey(byte[] b) {
        this(new ByteArrayInputStream(b));
    }
    
    /**
     * Constructs a new private key from an input stream
     * @param is an input stream
     * @param params the NtruSign parameters to use
     * @throws NtruException if an {@link IOException} occurs
     */
    public SignaturePrivateKey(InputStream is) {
        bases = new ArrayList<Basis>();
        
        DataInputStream dataStream = new DataInputStream(is);
        try {
            N = dataStream.readShort();
            q = dataStream.readShort();
            byte flags = dataStream.readByte();
            sparse = (flags&1) != 0;
            polyType = (flags&4)==0 ? TernaryPolynomialType.SIMPLE : TernaryPolynomialType.PRODUCT;
            basisType = ((flags&8)==0) ? BasisType.STANDARD : BasisType.TRANSPOSE;
            keyNormBoundSq = dataStream.readFloat();
            
            int numBases = is.read();
            for (int i=0; i<numBases; i++)
                // include a public key h[i] in all bases except for the first one
                add(new Basis(is, N, q, sparse, polyType, basisType, keyNormBoundSq, i!=0));
        } catch(IOException e) {
            throw new NtruException(e);
        }
    }
    
    /**
     * Constructs a private key that contains no bases
     */
    SignaturePrivateKey(SignatureParameters params) {
        N = params.N;
        q = params.q;
        sparse = params.sparse;
        polyType = params.polyType;
        basisType = params.basisType;
        keyNormBoundSq = params.keyNormBoundSq;
        
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
    
    int getNumBases() {
        return bases.size();
    }
    
    /**
     * Converts the key to a byte array
     * @return the encoded key
     */
   public byte[] getEncoded() {
       int numBases = bases.size();
       
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(os);
        try {
            dataStream.writeShort(N);
            dataStream.writeShort(q);
            
            int flags = sparse ? 1 : 0;
            flags |= polyType==TernaryPolynomialType.PRODUCT ? 4 : 0;
            flags |= basisType==BasisType.TRANSPOSE ? 8 : 0;
            dataStream.write(flags);
            
            dataStream.writeFloat(keyNormBoundSq);
            dataStream.write(numBases);   // 1 byte
            
            for (int i=0; i<numBases; i++)
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
        } else if (!bases.equals(other.bases))
            return false;
        return true;
    }

    /** A NtruSign basis. Contains three polynomials <code>f, f', h</code>. */
    static class Basis {
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
}