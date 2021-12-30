package com.philipzhan.doorlocksystem.activity;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.widget.RadioButton;
import android.widget.TextView;
import android.widget.Toast;
import androidx.annotation.NonNull;
import android.provider.Settings;
import android.view.View;
import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import com.android.volley.DefaultRetryPolicy;
import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.toolbox.StringRequest;
import com.android.volley.toolbox.Volley;
import com.philipzhan.doorlocksystem.R;
import com.shasin.notificationbanner.Banner;

import java.net.URLEncoder;
import java.util.concurrent.Executor;

import static com.philipzhan.doorlocksystem.Crypto.generateSignature;
import static com.philipzhan.doorlocksystem.PublicDefinitions.validateServerAddress;

public class MainActivity extends AppCompatActivity {

    String deviceID;
    View rootView;
    Context context;

    SharedPreferences sharedPref;
    SharedPreferences.Editor editor;

    RadioButton httpsRadioButton;
    RadioButton httpRadioButton;
    TextView deviceIDTextView2;
    TextView serverAddressEditText2;

    final boolean[] isReturned = {false};

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        rootView = findViewById(android.R.id.content);

        context = getApplicationContext();
        deviceID = Settings.Secure.getString(getContentResolver(), Settings.Secure.ANDROID_ID);

        sharedPref = context.getSharedPreferences("com.philipzhan.doorlocksystem.preferences", Context.MODE_PRIVATE);
        editor = sharedPref.edit();

        deviceIDTextView2 = findViewById(R.id.deviceIDTextView2);
        serverAddressEditText2 = findViewById(R.id.serverAddressEditText2);
        httpsRadioButton = findViewById(R.id.httpsRadioButton);
        httpRadioButton = findViewById(R.id.httpRadioButton);

        deviceIDTextView2.setText("Your device ID is: " + deviceID);
    }

    public void openDoor(View view) {
        String serverAddress = serverAddressEditText2.getText().toString();
        if (!validateServerAddress(serverAddress)) {
//            Toast.makeText(context, "Server address is invalid.", Toast.LENGTH_SHORT).show();
//            System.out.println("Server address " + serverAddress + "is invalid.");
            Banner.make(rootView,MainActivity.this, Banner.ERROR, "Server address is invalid.", Banner.TOP, 2000).show();
            return;
        }

        Executor executor = ContextCompat.getMainExecutor(this);

        BiometricPrompt biometricPrompt = new BiometricPrompt(MainActivity.this, executor, new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                super.onAuthenticationSucceeded(result);
                try {
                    RequestQueue queue = Volley.newRequestQueue(context);
                    long timestamp = System.currentTimeMillis();
                    String dataString = "Open" + timestamp + deviceID + getPreSharedSecret();
                    String signatureString = generateSignature("MainKey", dataString);

                    String protocolText = "https";
                    if (httpRadioButton.isChecked()) {
                        protocolText = "http";
                    }

                    String url = protocolText + "://" + serverAddress + ":8443/open_door?type=Android&timestamp=" + timestamp + "&device_id=" + deviceID + "&signature=" + URLEncoder.encode(signatureString, "utf-8");
                    StringRequest stringRequest;

                    stringRequest = new StringRequest(Request.Method.GET, url, response -> {
                        if (response.equals("Door opening.")) {
//                            Toast.makeText(context, "Door opening.", Toast.LENGTH_SHORT).show();
                            Banner.make(rootView,MainActivity.this,Banner.SUCCESS,"Door opening.",Banner.TOP, 2000).show();
                        } else {
//                            Toast.makeText(context, response, Toast.LENGTH_SHORT).show();
                            Banner.make(rootView,MainActivity.this,Banner.ERROR,response,Banner.TOP, 2000).show();
                        }
                    }, error -> {
                        if (error.networkResponse == null) {
                            Banner.make(rootView,MainActivity.this,Banner.ERROR, error.getLocalizedMessage(), Banner.TOP, 2000).show();
                        } else {
                            Banner.make(rootView,MainActivity.this,Banner.ERROR,new String(error.networkResponse.data),Banner.TOP, 2000).show();
                        }
//                        Toast.makeText(context, new String(error.networkResponse.data), Toast.LENGTH_SHORT).show();
                    });
                    stringRequest.setRetryPolicy(new DefaultRetryPolicy(5000, 0, 1f));
                    queue.add(stringRequest);

                } catch (Exception e) {
                    e.printStackTrace();
                    Banner.make(rootView,MainActivity.this, Banner.ERROR, "Failed to open door.", Banner.TOP, 2000).show();
//                    Toast.makeText(context, "Failed to open door.", Toast.LENGTH_SHORT).show();
                }
            }

            @Override
            public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                super.onAuthenticationError(errorCode, errString);
//                Toast.makeText(context, errString, Toast.LENGTH_SHORT).show();
                Banner.make(rootView,MainActivity.this, Banner.ERROR, errString.toString(), Banner.TOP, 2000).show();
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
//                Toast.makeText(context, "Failed to authenticate user.", Toast.LENGTH_SHORT).show();
                Banner.make(rootView,MainActivity.this, Banner.ERROR, "Failed to authenticate user.", Banner.TOP, 2000).show();
            }
        });

        BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
                .setTitle("Biometric Authentication")
                .setDeviceCredentialAllowed(true)
                .build();

        biometricPrompt.authenticate(promptInfo);

    }

    public void deactivateDevice(View view) {
        String serverAddress = serverAddressEditText2.getText().toString();
        if (!validateServerAddress(serverAddress)) {
//            Toast.makeText(context, "Server address is invalid.", Toast.LENGTH_SHORT).show();
//            System.out.println("Server address " + serverAddress + "is invalid.");
            Banner.make(rootView,MainActivity.this, Banner.ERROR, "Server address is invalid.", Banner.TOP, 2000).show();
            return;
        }

        Executor executor = ContextCompat.getMainExecutor(this);

        BiometricPrompt biometricPrompt = new BiometricPrompt(MainActivity.this, executor, new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                super.onAuthenticationSucceeded(result);
                try {
                    RequestQueue queue = Volley.newRequestQueue(context);
                    long timestamp = System.currentTimeMillis();
                    String dataString = "Deactivate" + timestamp + deviceID + getPreSharedSecret();
                    String signatureString = generateSignature("MainKey", dataString);

                    String protocolText = "https";
                    if (httpRadioButton.isChecked()) {
                        protocolText = "http";
                    }

                    String url = protocolText + "://" + serverAddress + ":8443/deactivate_device?type=Android&timestamp=" + timestamp + "&device_id=" + deviceID + "&signature=" + URLEncoder.encode(signatureString, "utf-8");
                    StringRequest stringRequest;
                    stringRequest = new StringRequest(Request.Method.GET, url, response -> {
                        if (response.equals("Device deactivated.")) {
                            Toast.makeText(context, "Device deactivated.", Toast.LENGTH_SHORT).show();
                            editor.putBoolean("isRegistered", false);
                            editor.apply();
                            finishAffinity();
                        } else {
                            Toast.makeText(context, response, Toast.LENGTH_SHORT).show();
                        }
                    }, error -> {
                        if (error.networkResponse == null) {
                            Banner.make(rootView, MainActivity.this, Banner.ERROR, error.getLocalizedMessage(), Banner.TOP, 2000).show();
                        } else {
                            Banner.make(rootView, MainActivity.this, Banner.ERROR, new String(error.networkResponse.data), Banner.TOP, 2000).show();
                        }
                    });
                    stringRequest.setRetryPolicy(new DefaultRetryPolicy(5000, 0, 1f));
                    queue.add(stringRequest);
                } catch (Exception e) {
                    e.printStackTrace();
                    Toast.makeText(context, "Failed to deactivate device.", Toast.LENGTH_SHORT).show();
                }
            }

            @Override
            public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                super.onAuthenticationError(errorCode, errString);
//                Toast.makeText(context, errString, Toast.LENGTH_SHORT).show();
                Banner.make(rootView,MainActivity.this, Banner.ERROR, errString.toString(), Banner.TOP, 2000).show();
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
//                Toast.makeText(context, "Failed to authenticate user.", Toast.LENGTH_SHORT).show();
                Banner.make(rootView,MainActivity.this, Banner.ERROR, "Failed to authenticate user.", Banner.TOP, 2000).show();
            }
        });

        BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
                .setTitle("Biometric Authentication")
                .setDeviceCredentialAllowed(true)
                .build();

        biometricPrompt.authenticate(promptInfo);
    }

    public String getPreSharedSecret() {
        return sharedPref.getString("PreSharedSecret", null);
    }

    public void exportPublicKey(View view) {

    }

    public void exportPrivateKey(View view) {

    }
}