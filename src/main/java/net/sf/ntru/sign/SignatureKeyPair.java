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