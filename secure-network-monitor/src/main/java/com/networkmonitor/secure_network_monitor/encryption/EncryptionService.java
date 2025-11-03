package com.networkmonitor.secure_network_monitor.encryption;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * NEW EncryptionService that loads a real key from a KeyStore.
 */
@Service
public class EncryptionService {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;

    private SecretKey myKey; // This will hold our strong key from the file

    /**
     * This is the constructor. It runs ONCE when the app starts.
     * It reads the application.properties and loads the key from the file.
     */
    public EncryptionService(
            @Value("${keystore.path}") String keyStorePath,
            @Value("${keystore.password}") String keyStorePassword,
            @Value("${keystore.key.alias}") String keyAlias,
            @Value("${keystore.type}") String keyStoreType)
            throws Exception {

        System.out.println("--- LOADING SECRET KEY FROM KEYSTORE ---");

        // 1. Create a KeyStore object of the correct type
        KeyStore keyStore = KeyStore.getInstance(keyStoreType); // "PKCS12"

        // 2. Load the .p12 file from the path
        FileInputStream fis = new FileInputStream(keyStorePath);
        keyStore.load(fis, keyStorePassword.toCharArray());
        fis.close();

        // 3. Get the key from the KeyStore
        // We use the same password for the key as we did for the store
        KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(
                keyAlias,
                new KeyStore.PasswordProtection(keyStorePassword.toCharArray())
        );

        this.myKey = secretKeyEntry.getSecretKey();
        System.out.println("--- SECRET KEY LOADED SUCCESSFULLY ---");
    }

    /**
     * The new encrypt method is SIMPLER.
     * It no longer needs a password because it already has the real key.
     */
    public String encrypt(String data) throws Exception {
        byte[] iv = generateRandomBytes(IV_LENGTH_BYTE);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);

        // Uses the key we loaded from the file
        cipher.init(Cipher.ENCRYPT_MODE, this.myKey, spec);

        byte[] encryptedData = cipher.doFinal(data.getBytes());

        // We only need to store the IV + data (no salt needed)
        byte[] combined = new byte[iv.length + encryptedData.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encryptedData, 0, combined, iv.length, encryptedData.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    /**
     * The new decrypt method is also SIMPLER.
     */
    public String decrypt(String encryptedData) throws Exception {
        byte[] combined = Base64.getDecoder().decode(encryptedData);

        // Unpack the IV and the encrypted data
        byte[] iv = new byte[IV_LENGTH_BYTE];
        byte[] encrypted = new byte[combined.length - IV_LENGTH_BYTE];
        System.arraycopy(combined, 0, iv, 0, iv.length);
        System.arraycopy(combined, iv.length, encrypted, 0, encrypted.length);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);

        // Uses the key we loaded from the file
        cipher.init(Cipher.DECRYPT_MODE, this.myKey, spec);

        byte[] decryptedData = cipher.doFinal( encrypted);
        return new String(decryptedData);
    }

    private byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }
}