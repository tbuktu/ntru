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

import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import net.sf.ntru.encrypt.EncryptionKeyPair;
import net.sf.ntru.encrypt.EncryptionParameters;
import net.sf.ntru.encrypt.EncryptionPublicKey;
import net.sf.ntru.encrypt.NtruEncrypt;

/**
 * Demonstrates how to encrypt data that is longer than the maximum message length
 * for pure NTRUEncrypt (see {@link EncryptionParameters#getMaxMessageLength()}).<br/>
 * First the data is encrypted with AES and then the AES key is encrypted with
 * NTRUEncrypt.<br/>
 * Decryption works the reverse way, by decrypting the AES key with NTRU and then
 * decrypting the data with AES.
 */
public class AesExample {
    
    /**
     * @param args unused
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        new AesExample().run();
    }
    
    private void run() throws Exception {
        String plainText =
                "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor" +
                "incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud" +
                "exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute" +
                "irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla" +
                "pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui" +
                "officia deserunt mollit anim id est laborum.";
        
        // NTRU and AES parameters
        String aesMode = "AES/CBC/PKCS5Padding";
        int aesLength = 128;
        EncryptionParameters ntruParams = EncryptionParameters.APR2011_439_FAST;
        
        // generate an NtruEncrypt key pair
        NtruEncrypt ntru = new NtruEncrypt(ntruParams);
        EncryptionKeyPair ntruKeyPair = ntru.generateKeyPair();
        
        System.out.println("Unencrypted text = " + plainText.substring(0, 50) + "...");
        System.out.println("Plain txt length = " + plainText.length());
        System.out.println("Max. NTRU length = " + ntruParams.getMaxMessageLength());
        
        // encrypt the text
        byte[] encrypted = encrypt(plainText.getBytes(), ntruKeyPair.getPublic(), aesMode, aesLength, ntruParams);
        
        System.out.println("Encrypted length = " + encrypted.length +
                " (NTRU=" + ntruParams.getOutputLength() + ", AES=" + (encrypted.length-ntruParams.getOutputLength()) + ")");
        
        // decrypt
        String decrypted = new String(decrypt(encrypted, ntruKeyPair, aesMode, aesLength, ntruParams));
        
        System.out.println("Decrypted text   = " + decrypted.substring(0, 50) + "...");
        System.out.println("Decrypted length = " + decrypted.length());
    }
    
    /**
     * Encrypts a <code>byte</code> array of arbitrary length using NTRU and AES.
     * @param plainText the data to encrypt
     * @param pubKey the public key to encrypt the data with
     * @param aesMode a valid {@link Cipher} identifier
     * @param aesLength the length of the AES key in bits; note that keys longer than 128
     *        bits may require installation of the
     *        <a href="http://www.oracle.com/technetwork/java/javase/downloads/index.html">
     *        Unlimited Strength Jurisdiction Policy Files</a> or alternatively the use of
     *        an unrestricted AES implementation such as
     *        <a href="http://bouncycastle.org/java.html">Bouncy Castle</a>
     * @param ntruParams an NtruEncrypt parameter set
     * @return a <code>byte</code> array containing the AES key, the IV, and the encrypted data
     * @throws Exception
     */
    private byte[] encrypt(byte[] plainText, EncryptionPublicKey pubKey, String aesMode, int aesLength, EncryptionParameters ntruParams) throws Exception {
        // generate an AES key
        SecretKey aesKey = generateAesKey(aesLength);
        SecretKeySpec aesKeySpec = new SecretKeySpec(aesKey.getEncoded(), "AES");
        
        // encrypt the text with AES
        Cipher cipher = Cipher.getInstance(aesMode);
        cipher.init(Cipher.ENCRYPT_MODE, aesKeySpec);   // this also generates an IV
        byte[] iv = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
        byte[] aesEncrypted = cipher.doFinal(plainText);
        
        // encrypt AES key and IV with NTRU
        NtruEncrypt ntru = new NtruEncrypt(ntruParams);
        byte[] aesKeyArr = aesKey.getEncoded();
        byte[] keyAndIv = concat(aesKeyArr, iv);
        byte[] ntruEncrypted = ntru.encrypt(keyAndIv, pubKey);
        
        // put everything in one byte array
        return concat(ntruEncrypted, aesEncrypted);
    }
    
    /**
     * Decrypts a <code>byte</code> array encrypted with
     * {@link #encrypt(byte[], EncryptionPublicKey, String, int, EncryptionParameters)}.
     * @param encrypted encrypted data consisting of an NTRU-encrypted block of length
     *        <code>ntruParams.getOutputLength()</code> followed by the AES-encrypted
     *        plain text. The NTRU block must contain the AES key of length
     *        <code>aesLength/8 bytes</code> followed by the initialization vector of
     *        length <code>aesLength/8 bytes</code>.
     * @param kp an NtruEncrypt key pair
     * @param aesMode a valid {@link Cipher} identifier
     * @param aesLength the length of the AES key in bits; note that keys longer than 128
     *        bits may require installation of the
     *        <a href="http://www.oracle.com/technetwork/java/javase/downloads/index.html">
     *        Unlimited Strength Jurisdiction Policy Files</a> or alternatively the use of
     *        an unrestricted AES implementation such as
     *        <a href="http://bouncycastle.org/java.html">Bouncy Castle</a>
     * @param ntruParams an NtruEncrypt parameter set
     * @return the decrypted data
     * @throws Exception
     */
    private byte[] decrypt(byte[] encrypted, EncryptionKeyPair kp, String aesMode, int aesLength, EncryptionParameters ntruParams) throws Exception {
        NtruEncrypt ntru = new NtruEncrypt(ntruParams);
        
        // decrypt the NTRU block to obtain the AES key and the IV
        byte[] ntruEncrypted = Arrays.copyOf(encrypted, ntruParams.getOutputLength());
        byte[] keyAndIv = ntru.decrypt(ntruEncrypted, kp);
        byte[] aesKeyArr = Arrays.copyOf(keyAndIv, aesLength/8);
        byte[] ivArr = Arrays.copyOfRange(keyAndIv, aesLength/8, 2*aesLength/8);
        
        // use the AES key and IV to decrypt the plain text
        byte[] aesEncrypted = Arrays.copyOfRange(encrypted, ntruEncrypted.length, encrypted.length);
        Cipher cipher = Cipher.getInstance(aesMode);
        SecretKeySpec aesKeySpec = new SecretKeySpec(aesKeyArr, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(ivArr);
        cipher.init(Cipher.DECRYPT_MODE, aesKeySpec, ivSpec);
        byte[] plainText = cipher.doFinal(aesEncrypted);
        
        return plainText;
    }
    
    /**
     * Generates a random AES key.
     * @param numBits key size in bits
     * @return
     * @throws Exception
     */
    private SecretKey generateAesKey(int numBits) throws Exception {
        KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
        aesKeyGen.init(numBits);
        return aesKeyGen.generateKey();
    }
    
    /**
     * Concatenates two <code>byte</code> arrays.
     * @param a
     * @param b
     * @return
     */
    private byte[] concat(byte[] a, byte[] b) {
        byte[] c = new byte[a.length+b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }
}