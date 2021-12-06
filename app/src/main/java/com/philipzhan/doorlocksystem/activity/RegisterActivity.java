package com.philipzhan.doorlocksystem.activity;

import android.content.*;
import android.net.Uri;
import android.provider.Settings;
import android.view.View;
import android.widget.*;
import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import androidx.core.content.FileProvider;
import com.philipzhan.doorlocksystem.R;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.pkcs.PKCS10CertificationRequest;

import java.io.*;
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

        context = getApplicationContext();
        cacheDir = context.getCacheDir();
        sharedPref = context.getSharedPreferences("com.philipzhan.doorlocksystem.preferences", Context.MODE_PRIVATE);
        editor = sharedPref.edit();

        deviceIDTextView = findViewById(R.id.deviceIDTextView);
        nameEditText = findViewById(R.id.nameEditText);
        certificateEditText = findViewById(R.id.certificateEditText);
        deviceID = Settings.Secure.getString(getContentResolver(), Settings.Secure.ANDROID_ID);
        deviceIDTextView.setText("Your device ID is: " + deviceID);

        if (sharedPref.getBoolean("isRegistered", false)) {
            Intent mainActivity = new Intent(this, MainActivity.class);
            startActivity(mainActivity);
        }

    }

    public void generateCertificateSigningRequest(View view) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IOException, OperatorCreationException {
        if (nameEditText.getText().toString().length() == 0) {
            Toast.makeText(context, "Enter a name before continuing.", Toast.LENGTH_SHORT).show();
            return;
        }
        keyPair = generateRSAKeyPair("MainKey");
        PKCS10CertificationRequest csr = generateCSR(keyPair, nameEditText.getText().toString());
        String textCSR = "-----BEGIN CERTIFICATE REQUEST-----\n" +
                Base64.getEncoder().encodeToString(csr.getEncoded()) +
                "\n-----END CERTIFICATE REQUEST-----\n";

        File csrFile = File.createTempFile(deviceID, ".csr", cacheDir);
        System.out.println("csrFile Path: " + csrFile.getAbsolutePath());
        FileOutputStream stream = new FileOutputStream(csrFile);
        stream.write(textCSR.getBytes(StandardCharsets.UTF_8));
        stream.close();

        Intent sendIntent = new Intent();
        Uri csrUri = FileProvider.getUriForFile(context, "com.philipzhan.doorlocksystem.provider", csrFile);
        sendIntent.setAction(Intent.ACTION_SEND);
        sendIntent.putExtra(Intent.EXTRA_STREAM, csrUri);
        sendIntent.setType("text/plain");

        Intent shareIntent = Intent.createChooser(sendIntent, null);
        startActivity(shareIntent);

        ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        ClipData clip = ClipData.newPlainText("simple text", textCSR);
        // Set the clipboard's primary clip.
        clipboard.setPrimaryClip(clip);

    }

    public void verifyCertificate(View view) throws CertificateException, IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException {
        String certText = certificateEditText.getText().toString();
        if (certText.length() == 0) {
            Toast.makeText(context, "Response is empty.", Toast.LENGTH_SHORT).show();
        }

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream caInputStream = getAssets().open("Door_Lock_CA.crt");
        Certificate caCertificate = cf.generateCertificate(caInputStream);

        try {
            InputStream inputStream = new ByteArrayInputStream(certText.getBytes(StandardCharsets.UTF_8));
            Certificate certificate = cf.generateCertificate(inputStream);
            certificate.verify(caCertificate.getPublicKey());
            RSAPublicKey certificatePublicKey = (RSAPublicKey) certificate.getPublicKey();
            RSAPublicKey keyPairPublicKey = (RSAPublicKey) keyPair.getPublic();
            if (certificatePublicKey.getPublicExponent().equals(keyPairPublicKey.getPublicExponent()) && certificatePublicKey.getModulus().equals(keyPairPublicKey.getModulus())) {
                Toast.makeText(context, "Certificate is valid, registering with Raspberry Pi.", Toast.LENGTH_SHORT).show();
                editor.putBoolean("isRegistered", true);
                editor.apply();
            } else {
                Toast.makeText(context, "Certificate mismatches. Regenerate a signing request.", Toast.LENGTH_SHORT).show();
            }

        } catch (Exception e) {
            e.printStackTrace();
            Toast.makeText(context, "Response is invalid.", Toast.LENGTH_SHORT).show();
        }
    }

}