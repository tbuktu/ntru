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

package net.sf.ntru.demo;

import net.sf.ntru.encrypt.EncryptionKeyPair;
import net.sf.ntru.encrypt.EncryptionParameters;
import net.sf.ntru.encrypt.NtruEncrypt;
import net.sf.ntru.sign.NtruSign;
import net.sf.ntru.sign.SignatureKeyPair;
import net.sf.ntru.sign.SignatureParameters;

/**
 * A simple program demonstrating the use of NtruEncrypt and NtruSign.
 */
public class SimpleExample {
    
    public static void main(String[] args) {
        encrypt();
        System.out.println();
        sign();
    }

    private static void encrypt() {
        System.out.println("NTRU encryption");
        
        // create an instance of NtruEncrypt with a standard parameter set
        NtruEncrypt ntru = new NtruEncrypt(EncryptionParameters.APR2011_439_FAST);

        // create an encryption key pair
        EncryptionKeyPair kp = ntru.generateKeyPair();

        String msg = "The quick brown fox";
        System.out.println("  Before encryption: " + msg);

        // encrypt the message with the public key created above
        byte[] enc = ntru.encrypt(msg.getBytes(), kp.getPublic());

        // decrypt the message with the private key created above
        byte[] dec = ntru.decrypt(enc, kp);

        // print the decrypted message
        System.out.println("  After decryption:  " + new String(dec));
    }

    private static void sign() {
        System.out.println("NTRU signature");
        
        // create an instance of NtruSign with a test parameter set
        NtruSign ntru = new NtruSign(SignatureParameters.TEST157);
        
        // create an signature key pair
        SignatureKeyPair kp = ntru.generateKeyPair();

        String msg = "The quick brown fox";
        System.out.println("  Message: " + msg);
        
        // sign the message with the private key created above
        byte[] sig = ntru.sign(msg.getBytes(), kp);
        
        // verify the signature with the public key created above
        boolean valid = ntru.verify(msg.getBytes(), sig, kp.getPublic());
        
        System.out.println("  Signature valid? " + valid);
    }
}