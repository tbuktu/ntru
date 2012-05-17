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