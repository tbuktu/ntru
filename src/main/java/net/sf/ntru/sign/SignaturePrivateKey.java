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
}