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
            String sigKPStr = "J4OJIbN2X3IjPY2XGl/lHt6GNy/Z/EEftitY31HqqhN0qZZ+HY+sU9+mr8M52ySitkWf9cbARYeW" +
                    "F6wQBzCHbmf1va4Iq6adLhshdVzW5p+5BpGUuIzIG9NjTmnBpD3Zo/dN8bXZMhmMp0+NBotjxrlD" +
                    "G9alFKlArFNt8fGkKwG43gbAFcPp3cmRScPt5jEg5s6M93VHlUyE2jD0zxX4ehoQawV3IC0p5SGt" +
                    "dR7cr1pnxSmNH/Xw5K7APIzEx1IYSAytAaY4GjxLcEGr+yqDW9oJ6FBoTutSVxNcdIIGVoT0LKNe" +
                    "3u2vkVdXBHjAiS0ji6ZwFWuMMzy0m5KzxwwhJnqXi8QhmWgsHLkuCOYUMBAQ4G93yOObnVXf5dhV" +
                    "mCEEZ3K36TlihD/EuYFh53mw4nrx7z1ta7Y6DUpbxgN3Jnb1Ryvv6wxc2HNXXjz6OL+GX4nbOZje" +
                    "3Rrd8lEWR6Bx70PyFcX+S7La0nBgTNHR7exOwQYal73z+brR0ng91+5l3OALFaqT3nrUxknPqcGa" +
                    "FRA3m+6nvNtaacfPRmKq9jiY1tPq0e0OIEEvsbSEBSkKepAkOlgURLcHL7491VJ9siCA5/Y7FPyl" +
                    "FPCM0LPrSF826m86VSH5MNaQTldCvqRVHRiPzdzoE9tJUVl1ecmzi8udIKbzl7c6i1fcxhut/xY/" +
                    "M7B8UuujhBhjd4u1f9W6Znxkf5zsQoGDHUzjnUha9kpT/jjAIuiIv1euiW0GSnPQ2ki53DbUgLUq" +
                    "+7/a7opSg0sY38m1U0ImL389A2OCElhxpy0f+2+zhjMeDghoQBCwQIaHyCQqtAEKAMJAxFKXv1xm" +
                    "M6QBctjDJaohjn10ZTMcqIEhuhERmvBEMAEoARG6wI+qAOVoSEymQhhsCAUz3gGPjFQlLYEBIGgB" +
                    "HNaBE6JcxjSuAUCgxEJgQhW3WMY0PBiFMTICkp/ExTFHuEU2uGGWwQAY0MEc6FARHwgBFiqBEqFc" +
                    "pS2kAQKYgAh8AIUwAOIQGAEAQAMdBOGMcTilKjCQQhY24pKxtGUwTDDDNzRyFKkAB0iBEaDSFyBY" +
                    "gxuq4Q56RAQulgEE2MAVhIGOjYiEJU0BP7CFNADiEpjI5DVYMIQpZkGLeiAkLkfQwyV+EQ7aAANA" +
                    "wiM0YRibdY1N/+4ZrmIWGtkYfAo/LYMWwiaKe7EieD9PmqRjb0Oa4CfzQes5Ott+cZcILRROffkC" +
                    "akfnkWS0Uf+vVEcySkCZ32wQtwedfyS9uGQQ7bfzioXGv53rrN2+UbJT/ie6KtiIfoycutXEWfAj" +
                    "o2xTJW+YG/AKXodCQuUa2pGrEsarMUMItXGP1D5kwZ+AryIuZBxAqRRPQabK7vg8JuBIkXckL0hs" +
                    "SvtG0ET5IAco53wY/0ZPE9VtasRjf34/RNX9qR9tLg+SmI90j/s8D4oTp65i7e+loYQgGgfnU6e0" +
                    "C4uemHHDtWzANGifs6vZrz8hcBr3gpydnqkvuy6qeDUPGrzWeZA9DJCyvYJtqchmo6+1OV/jUROE" +
                    "di2J43LPq2VJFlfiY5FOn5ykSmcRSbuuto5FdfRKNovHLwHJ0tOEu6ifgQk9qrzfRnjxHsCBhclv" +
                    "zKnT0rF3nMA2E35TJ9kN4TufPD7tCimPrGvJZuYo6E2tew40jJRgMuQtpO8jQnHO1++bHikgDzqO" +
                    "XkK8vUlZ/94lVIGcsgpnNC70E+3JUGXMrPd9QK+alkzfjExb01AOBmQ5Y5R3eqVfHqwTSBjBICoX" +
                    "0kaggEjQjW8fjbefC0RIbJjIDHzOPihCSG2fPb/3MSyERJNg0Fv81qbSGBsajVzeNMI3BjnAmdN+" +
                    "4D8TQs2fVZgUUFzeSBG1w3IZZXP39ZtW0xJCyFyoKBUH8O6BRoOBRXnE9X+ulC+gSU4PwPYzt9cA" +
                    "XnmzBcbZ26m+Q70K8XHuvGzP/kc7GYB8vvk5sjq/TiOiA1bhS9wJ";
            return new SignatureKeyPair(Base64.decode(sigKPStr, Base64.DEFAULT), SIGNATURE_PARAMS);
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