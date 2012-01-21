package net.sf.ntru.demo;

import java.text.DecimalFormat;

import net.sf.ntru.encrypt.EncryptionKeyPair;
import net.sf.ntru.encrypt.EncryptionParameters;
import net.sf.ntru.encrypt.NtruEncrypt;
import net.sf.ntru.sign.NtruSign;
import net.sf.ntru.sign.SignatureKeyPair;
import net.sf.ntru.sign.SignatureParameters;
import android.app.Activity;
import android.graphics.Color;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.SystemClock;
import android.util.Base64;
import android.widget.LinearLayout;
import android.widget.TextView;

public class NtruActivity extends Activity {
    private LinearLayout layout;
    
    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        setContentView(layout);
        
        new EncryptTask().execute();
    }
    
    /**
     * Generates an encryption key pair, encrypts a message, and decrypts it.
     * Prints text on the screen for each step.
     */
    private class EncryptTask extends AsyncTask<Void, Void, EncryptionKeyPair> {
        NtruEncrypt ntru;
        TextView view;
        long startTime;   // the time key generation started
        
        EncryptTask() {
            println("NTRU encryption", Color.WHITE);
            
            ntru = new NtruEncrypt(EncryptionParameters.APR2011_439_FAST);
            
            view = new TextView(NtruActivity.this);
            view.setTextColor(Color.GREEN);
            view.setText("  Generating key pair...");
            layout.addView(view);
        }
        
        @Override
        protected EncryptionKeyPair doInBackground(Void... params) {
            startTime = SystemClock.uptimeMillis();
            return ntru.generateKeyPair();
        }
        
        @Override
        protected void onPostExecute(EncryptionKeyPair kp) {
            long endTime = SystemClock.uptimeMillis();
            String duration = DecimalFormat.getNumberInstance().format((endTime-startTime)/1000.0);
            view.append(" done (" + duration + "s)");
            encryptDecrypt(ntru, kp);
        }
        
        private void encryptDecrypt(NtruEncrypt ntru, EncryptionKeyPair kp) {
            String msg = "The quick brown fox";
            println("  Before encryption: ", Color.GREEN, msg, Color.GRAY);
            
            byte[] enc = ntru.encrypt(msg.getBytes(), kp.getPublic());
            String encStr = Base64.encodeToString(enc, Base64.DEFAULT).substring(0, 20) + "...";
            println("  After encryption: ", Color.GREEN, encStr, Color.GRAY);
            
            byte[] dec = ntru.decrypt(enc, kp);
            println("  After decryption: ", Color.GREEN, new String(dec), Color.GRAY);
            
            println("", Color.WHITE);
            new SignTask().execute();
        }
    }
    
    /**
     * Generates a signature key pair, signs a message, and verifies the signature.
     * Prints text on the screen for each step.
     */
    private class SignTask extends AsyncTask<Void, Void, SignatureKeyPair> {
        NtruSign ntru;
        TextView view;
        long startTime;   // the time key generation started
        
        SignTask() {
            println("NTRU signature", Color.WHITE);
            
            ntru = new NtruSign(SignatureParameters.TEST157_PROD);
            
            println("  Generating key pair", Color.GREEN);
            view = new TextView(NtruActivity.this);
            view.setTextColor(Color.GREEN);
            view.setText("  (may take several minutes)...");
            layout.addView(view);
        }
        
        @Override
        protected SignatureKeyPair doInBackground(Void... params) {
            startTime = SystemClock.uptimeMillis();
            return ntru.generateKeyPair();
        }
        
        @Override
        protected void onPostExecute(SignatureKeyPair kp) {
            long endTime = SystemClock.uptimeMillis();
            String duration = DecimalFormat.getNumberInstance().format((endTime-startTime)/1000.0);
            view.append(" done (" + duration + "s)");
            signVerify(ntru, kp);
        }
        
        private void signVerify(NtruSign ntru, SignatureKeyPair kp) {
            String msg = "The quick brown fox";
            println("  Message: ", Color.GREEN, msg, Color.GRAY);
            
            byte[] sig = ntru.sign(msg.getBytes(), kp);
            String sigStr = Base64.encodeToString(sig, Base64.DEFAULT).substring(0, 20) + "...";
            println("  Signature: ", Color.GREEN, sigStr, Color.GRAY);
            
            boolean valid = ntru.verify(msg.getBytes(), sig, kp.getPublic());
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
        view.setTextColor(color2);
        view.setText(text2);
        row.addView(view);
        
        layout.addView(row);
    }
}