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