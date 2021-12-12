package com.philipzhan.doorlocksystem.activity;

import android.content.*;
import android.net.Uri;
import android.provider.Settings;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.*;
import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import androidx.core.content.FileProvider;
import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.toolbox.StringRequest;
import com.android.volley.toolbox.Volley;
import com.philipzhan.doorlocksystem.R;
import org.spongycastle.pkcs.PKCS10CertificationRequest;

import java.io.*;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.philipzhan.doorlocksystem.Crypto.*;

public class RegisterActivity extends AppCompatActivity {

    String deviceID;
    Context context;
    File cacheDir;
    SharedPreferences sharedPref;
    SharedPreferences.Editor editor;

    TextView deviceIDTextView;
    EditText serverAddressEditText;
    EditText certificateEditText;
    RadioButton httpsRadioButton;
    RadioButton httpRadioButton;

    KeyPair keyPair;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_register);

        // Initialize declared variables.
        context = getApplicationContext();
        cacheDir = context.getCacheDir();
        sharedPref = context.getSharedPreferences("com.philipzhan.doorlocksystem.preferences", Context.MODE_PRIVATE);
        editor = sharedPref.edit();
        deviceID = Settings.Secure.getString(getContentResolver(), Settings.Secure.ANDROID_ID);

        // Link declared UI components with view in xml file.
        deviceIDTextView = findViewById(R.id.deviceIDTextView);
        serverAddressEditText = findViewById(R.id.serverAddressEditText);
        certificateEditText = findViewById(R.id.certificateEditText);
        httpRadioButton = findViewById(R.id.httpRadioButton);
        httpsRadioButton = findViewById(R.id.httpsRadioButton);

        serverAddressEditText.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {

            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {

            }

            @Override
            public void afterTextChanged(Editable s) {
                editor.putString("ServerAddress", s.toString());
                editor.apply();
            }
        });
        serverAddressEditText.setText(getStoredServerAddress());

        // Update UI components.
        deviceIDTextView.setText("Your device ID is: " + deviceID);

        // Check if the device is already registered.
        if (sharedPref.getBoolean("isRegistered", false)) {
            // If the device is registered, switch to main activity.
            Intent mainActivity = new Intent(this, MainActivity.class);
            startActivity(mainActivity);
        }
    }

    public void generateNewCertificateSigningRequest(View view) {        // Generate an RSA key pair and generate a certificate signing request based on the key pair.
        try {
            generateCertificateSigningRequest(generateRSAKeyPair("MainKey"));
        } catch (Exception e) {
            Toast.makeText(context, e.getLocalizedMessage(), Toast.LENGTH_SHORT).show();
        }
    }

    public void shareExistingCertificateSigningRequest(View view){
        try {
            generateCertificateSigningRequest(getStoredRSAKeyPair("MainKey"));
        } catch (Exception e) {
            Toast.makeText(context, e.getLocalizedMessage(), Toast.LENGTH_SHORT).show();
        }
    }

    public void generateCertificateSigningRequest(KeyPair localKeyPair){
        try {
            PKCS10CertificationRequest csr = generateCSR(localKeyPair, deviceID);
            String textCSR = "-----BEGIN CERTIFICATE REQUEST-----\n" +
                    Base64.getEncoder().encodeToString(csr.getEncoded()) +
                    "\n-----END CERTIFICATE REQUEST-----\n";

            // Save generated CSR to a temporary cache location.
            File csrFile = File.createTempFile(deviceID, ".csr", cacheDir);
            FileOutputStream stream = new FileOutputStream(csrFile);
            stream.write(textCSR.getBytes(StandardCharsets.UTF_8));
            stream.close();

            generatePreSharedSecret();

            // Display a system share sheet with generated CSR.
            Intent sendIntent = new Intent();
            Uri csrUri = FileProvider.getUriForFile(context, "com.philipzhan.doorlocksystem.provider", csrFile);
            sendIntent.setAction(Intent.ACTION_SEND);
            sendIntent.putExtra(Intent.EXTRA_STREAM, csrUri);
            sendIntent.setType("text/plain");
            Intent shareIntent = Intent.createChooser(sendIntent, null);
            startActivity(shareIntent);

            // Copy generated CSR to clipboard.
            ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            ClipData clip = ClipData.newPlainText("simple text", textCSR);
            clipboard.setPrimaryClip(clip);
        } catch (Exception e) {
            Toast.makeText(context, e.getLocalizedMessage(), Toast.LENGTH_SHORT).show();
        }
    }

    public void clearAll(View view) {
        try {
            serverAddressEditText.setText("acl.philipzhan.com");
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            keyStore.deleteEntry("MainKey");
            certificateEditText.setText("");
        } catch (Exception e) {
            Toast.makeText(context, e.getLocalizedMessage(), Toast.LENGTH_SHORT).show();
        }
    }

    public void verifyCertificate(View view) {
        try {
            // Get server name from EditText input.
            if (!(validateServerAddress(serverAddressEditText.getText().toString()))) {
                Toast.makeText(context, "Server address is invalid.", Toast.LENGTH_SHORT).show();
                return;
            }

            // Get signed certificate from EditText input.
            String certText = certificateEditText.getText().toString();
            if (certText.length() == 0) {
                Toast.makeText(context, "Response is empty.", Toast.LENGTH_SHORT).show();
                return;
            }

            // Read the CA certificate in assets directory.
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            InputStream caInputStream = getAssets().open("Door_Lock_CA.crt");
            Certificate caCertificate = cf.generateCertificate(caInputStream);
            // Read the signed certificate entered in EditText.
            InputStream inputStream = new ByteArrayInputStream(certText.getBytes(StandardCharsets.UTF_8));
            Certificate certificate = cf.generateCertificate(inputStream);

            // Use the CA certificate to verify the signed certificate.
            certificate.verify(caCertificate.getPublicKey());

            // Check if the public key stored in AndroidKeyStore and the signed certificate matches.
            // If the exponent e and the modulus n are the same, they are the same key.
            RSAPublicKey certificatePublicKey = (RSAPublicKey) certificate.getPublicKey();
            RSAPublicKey keyPairPublicKey = (RSAPublicKey) getStoredRSAKeyPair("MainKey").getPublic();

            if (certificatePublicKey.getPublicExponent().equals(keyPairPublicKey.getPublicExponent()) && certificatePublicKey.getModulus().equals(keyPairPublicKey.getModulus())) {
                Toast.makeText(context, "Certificate is valid, registering with Raspberry Pi.", Toast.LENGTH_SHORT).show();
                RequestQueue queue = Volley.newRequestQueue(this);

                String protocol = "https";
                if (httpRadioButton.isChecked()) {
                    protocol = "http";
                }

                String url = protocol+"://"+serverAddressEditText.getText().toString()+":8443/register_user?type=" + "Android" + "&device_id=" + deviceID + "&pre_shared_secret=" + getPreSharedSecret() + "&certificate=" + URLEncoder.encode(certText, "utf-8");
                StringRequest stringRequest;
                stringRequest = new StringRequest(Request.Method.GET, url,
                        response -> {
                            Toast.makeText(context, "Successfully registered your device.", Toast.LENGTH_SHORT).show();
                            editor.putBoolean("isRegistered", true);
                            editor.apply();
                        }, error -> {
                    System.out.println();
                    Toast.makeText(context, error.toString(), Toast.LENGTH_SHORT).show();
                });
                queue.add(stringRequest);
            } else {
                Toast.makeText(context, "Certificate is valid, but mismatches with stroed key pair. Regenerate a signing request.", Toast.LENGTH_LONG).show();
            }
        } catch (Exception e) {
            e.printStackTrace();
            Toast.makeText(context, e.getLocalizedMessage(), Toast.LENGTH_SHORT).show();
        }
    }

    public void generatePreSharedSecret() {
        String str = randomHexString(6);
        editor.putString("PreSharedSecret", str);
        editor.apply();
    }

    public String getStoredServerAddress() {
        return sharedPref.getString("ServerAddress", "acl.philipzhan.com");
    }

    public String getPreSharedSecret() {
        return sharedPref.getString("PreSharedSecret", null);
    }

    public boolean validateServerAddress(String address) {
        if (address.length() == 0) {
            return false;
        }

        final String IPV4_REGEX =
                "^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                        "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                        "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                        "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";
        final Pattern IPv4_PATTERN = Pattern.compile(IPV4_REGEX);
        Matcher matcher4 = IPv4_PATTERN.matcher(address);
        if (matcher4.matches()) {
            return true;
        }

        final String IPV6_REGEX = "^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:)" +
                "{1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]" +
                "{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|" +
                "[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z" +
                "]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1" +
                "}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$";
        final Pattern IPv6_PATTERN = Pattern.compile(IPV6_REGEX);
        Matcher matcher6 = IPv4_PATTERN.matcher(address);
        if (matcher6.matches()) {
            return true;
        }

        final String DOMAIN_REGEX = "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\\-]*[A-Za-z0-9])$";
        final Pattern DOMAIN_PATTERN = Pattern.compile(DOMAIN_REGEX);
        Matcher matcher = DOMAIN_PATTERN.matcher(address);
        if (matcher.matches()) {
            return true;
        }

        return false;
    }

}