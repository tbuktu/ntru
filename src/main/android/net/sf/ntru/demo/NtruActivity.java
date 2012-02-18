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
        
        ntruEnc = new NtruEncrypt(EncryptionParameters.APR2011_439_FAST);
        ntruSig = new NtruSign(SignatureParameters.TEST157_PROD);
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
            new SigKeyGenTask().execute();
        }
    }
        
    /** Generates an signing key pair and calls SignTask when finished */
    private class SigKeyGenTask extends AsyncTask<Void, Void, Void> {
        long duration;
        TextView view;

        SigKeyGenTask() {
            println("NTRU signature", Color.WHITE);
            
            view = new TextView(NtruActivity.this);
            view.setTextColor(Color.GREEN);
            view.setText("  Generating key pair...");
            layout.addView(view);
        }
        
        @Override
        protected Void doInBackground(Void... arg0) {
            long startTime = SystemClock.uptimeMillis();
            sigKP = ntruSig.generateKeyPair();
            long endTime = SystemClock.uptimeMillis();
            duration = endTime - startTime;
            return null;
        }
        
        @Override
        protected void onPostExecute(Void result) {
            view.append(" done (" + duration/1000 + "s)");
            new SignTask().execute();
        }
    }
    
    /** Signs a message and calls VerifyTask */
    private class SignTask extends AsyncTask<Void, Void, byte[]> {
        TextView view;
        long startTime;
        
        SignTask() {
            println("  Message: ", Color.GREEN, msg, Color.GRAY);
            
            view = new TextView(NtruActivity.this);
            view.setTextColor(Color.GREEN);
            view.setText("  Signing...");
            layout.addView(view);
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