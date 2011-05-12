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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import net.sf.ntru.SignatureParameters.BasisType;

public class SignaturePrivateKey {
    private List<Basis> bases;
    
    public SignaturePrivateKey(byte[] b, SignatureParameters params) {
        bases = new ArrayList<Basis>();
        ByteBuffer buf = ByteBuffer.wrap(b);
        for (int i=0; i<=params.B; i++)
            // include a public key h[i] in all bases except for the first one
            add(new Basis(buf, params, i!=0));
    }
    
    public SignaturePrivateKey(InputStream is, SignatureParameters params) throws IOException {
        bases = new ArrayList<Basis>();
        for (int i=0; i<=params.B; i++)
            // include a public key h[i] in all bases except for the first one
            add(new Basis(is, params, i!=0));
    }
    
    SignaturePrivateKey() {
        bases = new ArrayList<Basis>();
    }
    
    void add(Basis b) {
        bases.add(b);
    }
    
    // Returns the i-th basis
    Basis getBasis(int i) {
        return bases.get(i);
    }
    
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
    
    public void writeTo(OutputStream os) throws IOException {
        os.write(getEncoded());
    }
    
    static class Basis {
        TernaryPolynomial f;
        IntegerPolynomial fPrime;
        IntegerPolynomial h;
        SignatureParameters params;
        
        Basis(TernaryPolynomial f, IntegerPolynomial fPrime, IntegerPolynomial h, SignatureParameters params) {
            this.f = f;
            this.fPrime = fPrime;
            this.h = h;
            this.params = params;
        }
        
        Basis(ByteBuffer buf, SignatureParameters params, boolean include_h) {
            int N = params.N;
            int q = params.q;
            boolean sparse = params.sparse;
            this.params = params;
            
            IntegerPolynomial fInt = IntegerPolynomial.fromBinary3Arith(buf, N);
            f = sparse ? new SparseTernaryPolynomial(fInt) : new DenseTernaryPolynomial(fInt);
            if (params.basisType == BasisType.STANDARD) {
                fPrime = IntegerPolynomial.fromBinary(buf, N, q);
                for (int i=0; i<fPrime.coeffs.length; i++)
                    fPrime.coeffs[i] -= q/2;
            }
            else
                fPrime = IntegerPolynomial.fromBinary3Arith(buf, N);
            if (include_h)
                h = IntegerPolynomial.fromBinary(buf, N, q);
        }
        
        Basis(InputStream is, SignatureParameters params, boolean include_h) throws IOException {
            int N = params.N;
            int q = params.q;
            boolean sparse = params.sparse;
            this.params = params;
            
            IntegerPolynomial fInt = IntegerPolynomial.fromBinary3Arith(is, N);
            f = sparse ? new SparseTernaryPolynomial(fInt) : new DenseTernaryPolynomial(fInt);
            if (params.basisType == BasisType.STANDARD) {
                fPrime = IntegerPolynomial.fromBinary(is, N, q);
                for (int i=0; i<fPrime.coeffs.length; i++)
                    fPrime.coeffs[i] -= q/2;
            }
            else
                fPrime = IntegerPolynomial.fromBinary3Arith(is, N);
            if (include_h)
                h = IntegerPolynomial.fromBinary(is, N, q);
        }
        
        void encode(OutputStream os, boolean include_h) throws IOException {
            int q = params.q;
            
            os.write(f.toIntegerPolynomial().toBinary3Arith());
            if (params.basisType == BasisType.STANDARD) {
                for (int i=0; i<fPrime.coeffs.length; i++)
                    fPrime.coeffs[i] += q/2;
                os.write(fPrime.toBinary(q));
            }
            else
                os.write(fPrime.toBinary3Arith());
            if (include_h)
                os.write(h.toBinary(q));
        }
    }
}