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

package net.sf.ntru.encrypt;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Random;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import net.sf.ntru.exception.NtruException;

/**
 * Deterministic random number generator initialized from a passphrase.<br/>
 * This class is <b>not</b> thread safe.
 */
public class PassphraseBasedPRNG extends Random {
    private static final long serialVersionUID = -3953874369831754610L;
    private static final int PBKDF2_ITERATIONS = 10000;
    
    private MessageDigest hash;
    private byte[] data;   // generated random data
    private int pos;   // next index in data
    
    /**
     * Creates a new <code>PassphraseBasedPRNG</code> from a passphrase and salt,
     * and seeds it with the output of <a href="http://en.wikipedia.org/wiki/PBKDF2">PBKDF2</a>.<br/>
     * PBKDF2 is intentionally slow, so this constructor should not be called more than
     * is necessary.
     * @param passphrase
     * @param salt
     * @throws NtruException if the JRE doesn't implement SHA-512
     */
    public PassphraseBasedPRNG(char[] passphrase, byte[] salt) {
        KeySpec ks = new PBEKeySpec(passphrase, salt, PBKDF2_ITERATIONS, 512);
        try {
            SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            data = f.generateSecret(ks).getEncoded();
            hash = MessageDigest.getInstance("SHA-512");
        } catch (InvalidKeySpecException e) {
            throw new NtruException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new NtruException(e);
        }
        pos = 0;
    }
    
    private PassphraseBasedPRNG() { }
    
    /**
     * Creates a new <code>PassphraseBasedPRNG</code> whose output differs but is a
     * function of this <code>PassphraseBasedPRNG</code>'s internal state.<br/>
     * This method does not call PBKDF2 and thus does not take nearly as long as the
     * constructor.
     * @return a new PassphraseBasedPRNG
     * @throws NtruException if the JRE doesn't implement SHA-512
     */
    public PassphraseBasedPRNG createBranch() {
        PassphraseBasedPRNG newRng = new PassphraseBasedPRNG();
        try {
            newRng.hash = MessageDigest.getInstance("SHA-512");
        } catch (NoSuchAlgorithmException e) {
            throw new NtruException(e);
        }
        newRng.data = data.clone();
        newRng.data[0]++;
        return newRng;
    }
    
    @Override
    public synchronized int next(int bits) {
        int value = 0;
        for (int i=0; i<bits; i+=8) {
            if (pos >= data.length) {
                data = hash.digest(data);
                pos = 0;
            }
            value = (value<<8) | (data[pos]&0xFF);
            pos++;
        }
        value = value << (32-bits) >>> (32-bits);
        return value;
    }
}