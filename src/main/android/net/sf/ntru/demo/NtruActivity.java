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
import android.app.Activity;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.SystemClock;
import android.util.Base64;
import android.widget.LinearLayout;
import android.widget.TextView;

/**
 * A simple non-interactive app that encrypts, decrypts, signs a test message and
 * verifies the signature. It prints the results on the screen including the time
 * it took for each operation.
 */
public class NtruActivity extends Activity {
    private static final SignatureParameters SIGNATURE_PARAMS = SignatureParameters.APR2011_439_PROD;
    private static final EncryptionParameters ENCRYPTION_PARAMS = EncryptionParameters.APR2011_439_FAST;
    
    private LinearLayout layout;
    NtruEncrypt ntruEnc;
    NtruSign ntruSig;
    EncryptionKeyPair encKP;
    SignatureKeyPair sigKP;
    String msg = "The quick brown fox";
    
    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        setContentView(layout);
        
        ntruEnc = new NtruEncrypt(ENCRYPTION_PARAMS);
        ntruSig = new NtruSign(SIGNATURE_PARAMS);
        new EncKeyGenTask().execute();
    }
    
    /** Generates an encryption key pair and calls EncryptTask when finished */
    private class EncKeyGenTask extends AsyncTask<Void, Void, Void> {
        long duration;
        TextView view;

        EncKeyGenTask() {
            println("NTRU encryption", Color.WHITE);
            
            view = new TextView(NtruActivity.this);
            view.setTextColor(Color.GREEN);
            view.setText("  Generating key pair...");
            layout.addView(view);
        }
        
        @Override
        protected Void doInBackground(Void... arg0) {
            long startTime = SystemClock.uptimeMillis();
            encKP = ntruEnc.generateKeyPair();
            long endTime = SystemClock.uptimeMillis();
            duration = endTime - startTime;
            return null;
        }
        
        @Override
        protected void onPostExecute(Void result) {
            view.append(" done (" + duration + "ms)");
            new EncryptTask().execute();
        }
    }
    
    /** Encrypts a message and calls DecryptTask */
    private class EncryptTask extends AsyncTask<Void, Void, byte[]> {
        TextView view;
        long startTime;
        
        EncryptTask() {
            println("  Before encryption: ", Color.GREEN, msg, Color.GRAY);
            
            view = new TextView(NtruActivity.this);
            view.setTextColor(Color.GREEN);
            view.setText("  Encrypting...");
            layout.addView(view);
        }
        
        @Override
        protected byte[] doInBackground(Void... params) {
            startTime = SystemClock.uptimeMillis();
            return ntruEnc.encrypt(msg.getBytes(), encKP.getPublic());
        }
        
        @Override
        protected void onPostExecute(byte[] encrypted) {
            long endTime = SystemClock.uptimeMillis();
            view.append(" done (" + (endTime-startTime) + "ms)");
            new DecryptTask(encrypted).execute();
        }
    }
    
    /** Decrypts a message and calls SigKeyGenTask */
    private class DecryptTask extends AsyncTask<Void, Void, byte[]> {
        TextView view;
        long startTime;
        byte[] encrypted;
        
        DecryptTask(byte[] encrypted) {
            this.encrypted = encrypted;
            
            String encStr = Base64.encodeToString(encrypted, Base64.DEFAULT).substring(0, 20) + "...";
            println("  After encryption: ", Color.GREEN, encStr, Color.GRAY);
            
            view = new TextView(NtruActivity.this);
            view.setTextColor(Color.GREEN);
            view.setText("  Decrypting...");
            layout.addView(view);
        }
        
        @Override
        protected byte[] doInBackground(Void... params) {
            startTime = SystemClock.uptimeMillis();
            return ntruEnc.decrypt(encrypted, encKP);
        }
        
        @Override
        protected void onPostExecute(byte[] decrypted) {
            long endTime = SystemClock.uptimeMillis();
            view.append(" done (" + (endTime-startTime) + "ms)");
            println("  After decryption: ", Color.GREEN, new String(decrypted), Color.GRAY);
            println("", Color.WHITE);
            new SignTask().execute();
        }
    }
        
    /** Signs a message and calls VerifyTask */
    private class SignTask extends AsyncTask<Void, Void, byte[]> {
        TextView view;
        long startTime;
        
        SignTask() {
            println("NTRU signature", Color.WHITE);
            println("  Using existing key pair", Color.GREEN);
            sigKP = getKeyPair();
            println("  Message: ", Color.GREEN, msg, Color.GRAY);
            
            view = new TextView(NtruActivity.this);
            view.setTextColor(Color.GREEN);
            view.setText("  Signing...");
            layout.addView(view);
        }
        
        private SignatureKeyPair getKeyPair() {
            String sigKPStr = "AbcIAIL1Qobon5XHmjNxKglpn1C9uHRdHgdG++sRW4ujoG5gp57hVpIxqZBU/tcP7elkNLbAMrks" +
                "K2l2LHLPdfZqrfo/vVF5WwQdP8IyBpx0fcYxsvz7IGP09YORwufaTkmoY3pRn3wl9XUAzAZedXhD" +
                "S5/y9aT8TWhB6lLCSa8nTvNgtAe+W/Ru591ttP4kBtr7yLnz0+MWE82a1Fwc1ytD78qw8IXiSW0o" +
                "DYE7TZbCDHeaGR9iHw8/NbUMl0Az9E7hvdKMvlNXhSzIsxzT29P1KCW48sm0NJoRwK7nKpREbMpn" +
                "580vM8qWEd3vbh2ccB/LOn3LDAB24NQvMQM/c0gV+1gCUy9qjelPZAlCr2g6XKrj9OHcBucA0cWA" +
                "6k9Gn4T2H3/z87Jenu+I9GNHkZVW7A1GHqR+evoxrsFRYISGrHc+hDmnNgvUo6hzg8FIxFFS4VBI" +
                "YxcRxmtqr6/nYCuULHW0AQtQ7S7Qtc1F4hZ06igc9Ew2mPPbFDYCMABCdKgVCP+bzXiAmJljSLzC" +
                "2tqbI+EZHN/8lZatxCngCAt73gLpKivliJuvhY8wbVMXrpZfdDn2JVun55gKH5u4+XDWLzVfBkEg" +
                "BoM9wjWrNaTaMyHgoGpVAiiQXnnq5ul+UXzsrWaAWefR2ZQW7/o9dVwFlS3p4tmVLdaymCev8sQR" +
                "jJ1zrfPn1wmitvqeRWjmn1mI9Usvh1cw9Oq8Zsg/aSbwHqKslVMG5HJajwmVc2gOCZkh1NfHxbs1" +
                "t2EHFmVb3pYdeDE9IcZZZSBn4kU+Vk0nXqLXMcnjmYxw0TYHQwkBtwgADUeZIAACAAkACVTgxTO0" +
                "gZGaNKUthQES0IEuhjENcwgFM6EBAAgACDGwAh6kgRW7bCY0MthBIhghiV2Y5DIABgAFCBCFREQC" +
                "lrEAhxCKWhRjGwAJAAkrsIIbbOENiYiEL7UBGNgAGECRDIPoZDSlAQAIAAglcEIa4pEVsQBGMhxg" +
                "AyAsQQ1y7CMjAAYABUkAAy2AUZGTADC4Rjj6IRMACQAJJJgDUYoClba8RTOdAQK4AArocIi+COY0" +
                "sgEACAAIVRjHOwDCFbAYBjIv4EEUqJCFgGiFNAAGAAUqeEQ1sgEQjgAiiAU9EpIWAAkACQMYgi0S" +
                "shOj+GUymwEhMEM09mEQqGxlNK8BAAgACAfIgRNUkQ54jCQsH3gBH3ohkrGQhjYABgAFOnDEI+5h" +
                "lMUArkDHQiiiFyJ6FG2e0sVos6FxsWgNwouRiHOSze24MFVnXVDUq94rycpGY69uuPY7QOD6VEey" +
                "sbP6K4j508LBeUHVkSIUnfSrYlvXRHaYp2iTHuZWEZQ5HX7YSeLCDVDMb7GsfIqXSP3NSyfFO9Am" +
                "SmY6wTiUykOWPbyQP8kU2a7rOBpLNy7lQO0wR0nNUBcPKeu+thivAm5DQgv7ZSIVcz4aDKkzAqIl" +
                "9dSmI5VFBGlCf9NVtU20a3S0txGjDt7aI0EiE/96WBvS+VI3bndxK9Y+ir6Nf5wAZ9iKGZKsRJkD" +
                "9tlmERgL0w56QjQxqear5AcXCykxSzqvDnF128krEVnNGmZfWqA49H+C8NYZmJgQh9M1LUsoKUWt" +
                "4ETETj/5THBrLkTlzt8dXe3JF71hh18h/m81Vxq3GXP6mEZsblC49EPokfguATnDlpWIySZ23i+h" +
                "lI9oVHpUINNyJvp3EsffKbtT/2CC8JW6Js2L5dw/jRi754UJHDOB76Cn4IF1kaOoifD84MRtb1WA" +
                "6k2O2g1JOexXU/vnI/Yr13rcqrt7EJJCL0OVvLlSxpJLR8wqv0z91F8NGhXwzS1fVwSqcRAU6NnR" +
                "LWtGjV4NbdD1lZ1BCtC5VqCs/PXL4iXWvEW27YSJX+Dk9WCtvds/OFV07j6daRpPeehcbAYtQQ12" +
                "y62sMrvRlSakD4eEioOk/Hj2eSKbmCtswYpSdcRbaiponZv77Gf3dSWRuK1pSV9nhPp5na08X6Ta" +
                "HKvSNIz98Bt9zzT37Qvz4cVDLxUrPfVrMxYwvmTAm1ejkP6V1Kw8Kp3K4RQ=";
            return new SignatureKeyPair(Base64.decode(sigKPStr, Base64.DEFAULT));
        }
        
        @Override
        protected byte[] doInBackground(Void... params) {
            startTime = SystemClock.uptimeMillis();
            return ntruSig.sign(msg.getBytes(), sigKP);
        }
        
        @Override
        protected void onPostExecute(byte[] signature) {
            long endTime = SystemClock.uptimeMillis();
            view.append(" done (" + (endTime-startTime) + "ms)");
            new VerifyTask(signature).execute();
        }
    }
    
    /** Verifies a signature */
    private class VerifyTask extends AsyncTask<Void, Void, Boolean> {
        TextView view;
        long startTime;
        byte[] signature;
        
        VerifyTask(byte[] signature) {
            this.signature = signature;
            
            String sigStr = Base64.encodeToString(signature, Base64.DEFAULT).substring(0, 20) + "...";
            println("  Signature: ", Color.GREEN, sigStr, Color.GRAY);
            
            view = new TextView(NtruActivity.this);
            view.setTextColor(Color.GREEN);
            view.setText("  Verifying...");
            layout.addView(view);
        }
        
        @Override
        protected Boolean doInBackground(Void... params) {
            startTime = SystemClock.uptimeMillis();
            return ntruSig.verify(msg.getBytes(), signature, sigKP.getPublic());
        }
        
        @Override
        protected void onPostExecute(Boolean valid) {
            long endTime = SystemClock.uptimeMillis();
            view.append(" done (" + (endTime-startTime) + "ms)");
            println("  Signature valid? ", Color.GREEN, String.valueOf(valid), Color.GRAY);

            println("", Color.WHITE);
            println("Finished!", Color.WHITE);
        }
    }
    
    private void println(String text, int color) {
        TextView view = new TextView(this);
        view.setTextColor(color);
        view.setText(text);
        layout.addView(view);
    }
    
    private void println(String text1, int color1, String text2, int color2) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        
        TextView view = new TextView(this);
        view.setTextColor(color1);
        view.setText(text1);
        row.addView(view);
        
        view = new TextView(this);
        view.setTypeface(Typeface.MONOSPACE);
        view.setTextColor(color2);
        view.setText(text2);
        row.addView(view);
        
        layout.addView(row);
    }
}