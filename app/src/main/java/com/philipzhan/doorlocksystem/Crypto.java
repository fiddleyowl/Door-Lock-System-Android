package com.philipzhan.doorlocksystem;

import android.security.keystore.*;
import org.spongycastle.asn1.pkcs.*;
import org.spongycastle.asn1.x500.*;
import org.spongycastle.asn1.x509.*;
import org.spongycastle.operator.*;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.pkcs.*;
import org.spongycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class Crypto {
    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
        keyPairGenerator.initialize(new KeyGenParameterSpec.Builder(
                "MainKey",
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY | KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setDigests(KeyProperties.DIGEST_SHA256,
                        KeyProperties.DIGEST_SHA512)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .build());
        return keyPairGenerator.generateKeyPair();
    }

    private final static String CN_PATTERN = "CN=%s, O=Southern University of Science and Technology, L=Shenzhen, S=Guangdong";
    public static PKCS10CertificationRequest generateCSR(KeyPair keyPair, String cn) throws IOException, OperatorCreationException {
        String principal = String.format(CN_PATTERN, cn);

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal(principal), keyPair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
        ContentSigner signer = csBuilder.build(keyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);

        return csr;
    }

    public String sha256(String stringToHash) throws NoSuchAlgorithmException {
        return sha256(stringToHash.getBytes(StandardCharsets.UTF_8));
    }

    public String sha256(byte[] byteArrayToHash) throws NoSuchAlgorithmException {
        return bytesToHex(MessageDigest.getInstance("SHA256").digest(byteArrayToHash));
    }

    private static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
}
