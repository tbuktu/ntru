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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

import net.sf.ntru.exception.NtruException;
import net.sf.ntru.sign.SignaturePrivateKey.Basis;

/** Contains a public and a private signature key */
public class SignatureKeyPair {
    SignaturePrivateKey priv;
    SignaturePublicKey pub;
    
    /**
     * Constructs a new key pair.
     * @param priv a private key
     * @param pub a public key
     */
    public SignatureKeyPair(SignaturePrivateKey priv, SignaturePublicKey pub) {
        this.priv = priv;
        this.pub = pub;
    }
    
    /**
     * Constructs a new key pair from a byte array
     * @param b an encoded key pair
     */
    public SignatureKeyPair(byte[] b) {
        this(new ByteArrayInputStream(b));
    }
    
    /**
     * Constructs a new key pair from an input stream
     * @param is an input stream
     * @throws NtruException if an {@link IOException} occurs
     */
    public SignatureKeyPair(InputStream is) {
        pub = new SignaturePublicKey(is);
        priv = new SignaturePrivateKey(is);
    }
    
    /**
     * Returns the private key
     * @return the private key
     */
    public SignaturePrivateKey getPrivate() {
        return priv;
    }
    
    /**
     * Returns the public key (verification key)
     * @return the public key
     */
    public SignaturePublicKey getPublic() {
        return pub;
    }

    /**
     * Tests if the key pair is valid.
     * @return <code>true</code> if the key pair is valid, <code>false</code> otherwise
     */
    public boolean isValid() {
        if (priv.N != pub.h.coeffs.length)
            return false;
        if (priv.q != pub.q)
            return false;
        
        int B = priv.getNumBases() - 1;
        for (int i=0; i<=B; i++) {
            Basis basis = priv.getBasis(i);
            if (!basis.isValid(i==0 ? pub.h : basis.h))
                return false;
        }
        
        return true;
    }
    
    /**
     * Converts the key pair to a byte array
     * @return the encoded key pair
     */
    public byte[] getEncoded() {
        byte[] pubArr = pub.getEncoded();
        byte[] privArr = priv.getEncoded();
        byte[] kpArr = Arrays.copyOf(pubArr, pubArr.length+privArr.length);
        System.arraycopy(privArr, 0, kpArr, pubArr.length, privArr.length);
        return kpArr;
    }
    
    /**
     * Writes the key pair to an output stream
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
        result = prime * result + ((priv == null) ? 0 : priv.hashCode());
        result = prime * result + ((pub == null) ? 0 : pub.hashCode());
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
        SignatureKeyPair other = (SignatureKeyPair) obj;
        if (priv == null) {
            if (other.priv != null)
                return false;
        } else if (!priv.equals(other.priv))
            return false;
        if (pub == null) {
            if (other.pub != null)
                return false;
        } else if (!pub.equals(other.pub))
            return false;
        return true;
    }
}