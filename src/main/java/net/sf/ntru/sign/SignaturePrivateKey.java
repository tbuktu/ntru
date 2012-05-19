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
import net.sf.ntru.sign.SignatureParameters.BasisType;
import net.sf.ntru.sign.SignatureParameters.TernaryPolynomialType;

/**
 * A NtruSign private key comprises one or more {@link Basis} of three polynomials each,
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
     */
    public SignaturePrivateKey(byte[] b) {
        this(new ByteArrayInputStream(b));
    }
    
    /**
     * Constructs a new private key from an input stream
     * @param is an input stream
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
}