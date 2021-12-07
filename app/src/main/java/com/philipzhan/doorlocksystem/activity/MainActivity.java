package com.philipzhan.doorlocksystem.activity;

import android.content.Context;
import android.content.SharedPreferences;
import android.widget.TextView;
import android.widget.Toast;
import androidx.annotation.NonNull;
import android.os.Build;
import android.provider.Settings;
import android.util.Log;
import android.view.View;
import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.toolbox.StringRequest;
import com.android.volley.toolbox.Volley;
import com.philipzhan.doorlocksystem.R;

import java.net.URLEncoder;
import java.util.concurrent.Executor;

import static com.philipzhan.doorlocksystem.Crypto.generateSignature;
import static com.philipzhan.doorlocksystem.Crypto.sha256;

public class MainActivity extends AppCompatActivity {

    String deviceID;
    Context context;

    SharedPreferences sharedPref;
    SharedPreferences.Editor editor;

    TextView deviceIDTextView2;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        context = getApplicationContext();
        deviceID = Settings.Secure.getString(getContentResolver(), Settings.Secure.ANDROID_ID);

        sharedPref = context.getSharedPreferences("com.philipzhan.doorlocksystem.preferences", Context.MODE_PRIVATE);
        editor = sharedPref.edit();

        deviceIDTextView2 = findViewById(R.id.deviceIDTextView2);

        deviceIDTextView2.setText("Your device ID is: " + deviceID);
    }

    @RequiresApi(api = Build.VERSION_CODES.R)
    public void openDoor(View view) {
        Executor executor = ContextCompat.getMainExecutor(this);
        //authentication succeed, continue tasts that requires auth
        //failed authenticating, stop tasks that requires auth
        BiometricPrompt biometricPrompt = new BiometricPrompt(MainActivity.this, executor, new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                super.onAuthenticationError(errorCode, errString);
                Toast.makeText(context, errString, Toast.LENGTH_SHORT).show();
            }

            @Override
            public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                super.onAuthenticationSucceeded(result);
                //authentication succeed, continue tasts that requires auth

                Long timestamp = System.currentTimeMillis();
                String signatureString;

                try {
                    signatureString = sha256(timestamp + deviceID + getPreSharedSecret());
                    RequestQueue queue = Volley.newRequestQueue(context);
                    String url = "https://acl.philipzhan.com/open?timestamp=" + timestamp + "&device_id=" + deviceID + "&pre_shared_secret=" + getPreSharedSecret() + "&signature=" + URLEncoder.encode(generateSignature("MainKey", signatureString), "utf-8");
                    StringRequest stringRequest;
                    stringRequest = new StringRequest(Request.Method.GET, url,
                            response -> {
                                Toast.makeText(context, "Successfully registered your device.", Toast.LENGTH_SHORT).show();
                            }, error -> {
                        Toast.makeText(context, error.networkResponse.toString(), Toast.LENGTH_SHORT).show();
                    });
                    queue.add(stringRequest);
                } catch (Exception e) {
                    e.printStackTrace();
                    Toast.makeText(context, "Failed to open door.", Toast.LENGTH_SHORT).show();
                }
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
                //failed authenticating, stop tasks that requires auth
            }
        });

        BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
                .setTitle("Biometric Authentication")
                .setSubtitle("Login using fingerprint authentication")
                .setNegativeButtonText("User App Password")
                .build();

        biometricPrompt.authenticate(promptInfo);

    }

    public void deactivateDevice(View view) {

    }

    public String getPreSharedSecret() {
        return sharedPref.getString("PreSharedSecret", null);
    }
}