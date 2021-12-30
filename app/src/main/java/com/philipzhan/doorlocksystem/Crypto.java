package com.philipzhan.doorlocksystem;

import android.content.SharedPreferences;
import android.security.keystore.*;
import org.spongycastle.operator.*;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.pkcs.*;
import org.spongycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Base64;

public class Crypto {

    SharedPreferences sharedPref;
    SharedPreferences.Editor editor;

    /**
     * Generates an RSA key pair.
     * @param alias Alias of the key pair in AndroidKeyStore. Use this alias to retrieve the key pair.
     * @return Returns the generated key pair.
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidAlgorithmParameterException
     */
    public static KeyPair generateRSAKeyPair(String alias) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
        keyPairGenerator.initialize(new KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY | KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setDigests(KeyProperties.DIGEST_SHA256,
                        KeyProperties.DIGEST_SHA512)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .build());
        return keyPairGenerator.generateKeyPair();
    }

    private final static String CN_PATTERN = "CN=%s, O=Southern University of Science and Technology, L=Shenzhen, S=Guangdong";
    public static PKCS10CertificationRequest generateCSR(KeyPair keyPair, String cn) throws OperatorCreationException {
        // Set X.509 certificate attributes.
        String principal = String.format(CN_PATTERN, cn);

        // Build a certificate signing request.
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal(principal), keyPair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
        ContentSigner signer = csBuilder.build(keyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);

        return csr;
    }

    public static KeyPair getStoredRSAKeyPair(String alias) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableEntryException {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        KeyStore.Entry entry = keyStore.getEntry(alias, null);
        PrivateKey privateKey = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
        PublicKey publicKey = keyStore.getCertificate(alias).getPublicKey();
        KeyPair keyPair = new KeyPair(publicKey, privateKey);
        return keyPair;
    }

    public static String generateSignature(String alias, String message) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableEntryException, InvalidKeyException, SignatureException {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        KeyStore.Entry entry = keyStore.getEntry(alias, null);
        PrivateKey privateKey = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
//        PublicKey publicKey = keyStore.getCertificate(alias).getPublicKey();
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(privateKey);
        s.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signature = s.sign();
        return bytesToHexString(signature);
    }

    public static String sha256(String stringToHash) throws NoSuchAlgorithmException {
        return sha256(stringToHash.getBytes(StandardCharsets.UTF_8));
    }

    public static String sha256(byte[] byteArrayToHash) throws NoSuchAlgorithmException {
        return bytesToHexString(MessageDigest.getInstance("SHA256").digest(byteArrayToHash));
    }

    public static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    public static String randomHexString(int length) {
        return bytesToHexString(randomBytes(length));
    }

    public static String randomBase64String(int length) {
        return Base64.getEncoder().encodeToString(randomBytes(length));
    }

    private static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();
    public static String bytesToHexString(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
}
