package com.philipzhan.doorlocksystem.activity;

import android.content.*;
import android.net.Uri;
import android.provider.Settings;
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
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.pkcs.PKCS10CertificationRequest;

import java.io.*;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import static com.philipzhan.doorlocksystem.Crypto.*;

public class RegisterActivity extends AppCompatActivity {

    String deviceID;
    Context context;
    File cacheDir;
    SharedPreferences sharedPref;
    SharedPreferences.Editor editor;

    TextView deviceIDTextView;
    EditText nameEditText;
    EditText certificateEditText;

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
        nameEditText = findViewById(R.id.nameEditText);
        certificateEditText = findViewById(R.id.certificateEditText);

        // Update UI components.
        deviceIDTextView.setText("Your device ID is: " + deviceID);

        // Check if the device is already registered.
        if (sharedPref.getBoolean("isRegistered", false)) {
            // If the device is registered, switch to main activity.
            Intent mainActivity = new Intent(this, MainActivity.class);
            startActivity(mainActivity);
        }

    }

    public void generateCertificateSigningRequest(View view) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IOException, OperatorCreationException {
        // Get name from EditText input.
        if (nameEditText.getText().toString().length() == 0) {
            Toast.makeText(context, "Enter a name before continuing.", Toast.LENGTH_SHORT).show();
            return;
        }
        // Generate an RSA key pair and generate a certificate signing request based on the key pair.
        keyPair = generateRSAKeyPair("MainKey");
        PKCS10CertificationRequest csr = generateCSR(keyPair, nameEditText.getText().toString());
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

    }

    public void verifyCertificate(View view) throws CertificateException, IOException {
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

        try {
            // Read the signed certificate entered in EditText.
            InputStream inputStream = new ByteArrayInputStream(certText.getBytes(StandardCharsets.UTF_8));
            Certificate certificate = cf.generateCertificate(inputStream);

            // Use the CA certificate to verify the signed certificate.
            certificate.verify(caCertificate.getPublicKey());

            // Check if the public key stored in AndroidKeyStore and the signed certificate matches.
            // If the exponent e and the modulus n are the same, they are the same key.
            RSAPublicKey certificatePublicKey = (RSAPublicKey) certificate.getPublicKey();
            RSAPublicKey keyPairPublicKey = (RSAPublicKey) keyPair.getPublic();
            if (certificatePublicKey.getPublicExponent().equals(keyPairPublicKey.getPublicExponent()) && certificatePublicKey.getModulus().equals(keyPairPublicKey.getModulus())) {
                Toast.makeText(context, "Certificate is valid, registering with Raspberry Pi.", Toast.LENGTH_SHORT).show();
                RequestQueue queue = Volley.newRequestQueue(this);
                String url ="https://acl.philipzhan.com/register_user?type="+"Android"+"&device_id="+deviceID+"&pre_shared_secret="+ getPreSharedSecret() +"&certificate="+URLEncoder.encode(certText, "utf-8");
                StringRequest stringRequest;
                stringRequest = new StringRequest(Request.Method.GET, url,
                        response -> {
                            Toast.makeText(context, "Successfully registered your device.", Toast.LENGTH_SHORT).show();
                            editor.putBoolean("isRegistered", true);
                            editor.apply();
                        }, error -> {
                    Toast.makeText(context, error.networkResponse.toString(), Toast.LENGTH_SHORT).show();
                });
                queue.add(stringRequest);
            } else {
                Toast.makeText(context, "Certificate mismatches. Regenerate a signing request.", Toast.LENGTH_SHORT).show();
            }
        } catch (Exception e) {
            e.printStackTrace();
            Toast.makeText(context, "Response is invalid.", Toast.LENGTH_SHORT).show();
        }
    }

    public String generatePreSharedSecret() {
        String str = randomHexString(6);
        editor.putString("PreSharedSecret", str);
        editor.apply();
        return str;
    }

    public String getPreSharedSecret() {
        return sharedPref.getString("PreSharedSecret", null);
    }

}