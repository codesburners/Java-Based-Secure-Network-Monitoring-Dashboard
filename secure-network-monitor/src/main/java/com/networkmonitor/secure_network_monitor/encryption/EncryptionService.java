package com.networkmonitor.secure_network_monitor.encryption;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.KeySpec;
import java.util.Base64;

@Service
public class EncryptionService {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
    private static final int SALT_LENGTH_BYTE = 16;

    // This static block is important for GCM to work
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // The constructor is now empty and will not crash
    public EncryptionService() {
        // No file loading needed
    }

    /**
     * This encrypt method matches the one called by PcapProcessingService.
     */
    public String encrypt(String data, String password) throws Exception {
        byte[] salt = generateRandomBytes(SALT_LENGTH_BYTE);
        byte[] iv = generateRandomBytes(IV_LENGTH_BYTE);

        SecretKey key = deriveKey(password, salt);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        byte[] encryptedData = cipher.doFinal(data.getBytes());
        byte[] combined = new byte[salt.length + iv.length + encryptedData.length];

        System.arraycopy(salt, 0, combined, 0, salt.length);
        System.arraycopy(iv, 0, combined, salt.length, iv.length);
        System.arraycopy(encryptedData, 0, combined, salt.length + iv.length, encryptedData.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    public String decrypt(String encryptedData, String password) throws Exception {
        byte[] combined = Base64.getDecoder().decode(encryptedData);

        byte[] salt = new byte[SALT_LENGTH_BYTE];
        byte[] iv = new byte[IV_LENGTH_BYTE];
        byte[] encrypted = new byte[combined.length - SALT_LENGTH_BYTE - IV_LENGTH_BYTE];

        System.arraycopy(combined, 0, salt, 0, salt.length);
        System.arraycopy(combined, salt.length, iv, 0, iv.length);
        System.arraycopy(combined, salt.length + iv.length, encrypted, 0, encrypted.length);

        SecretKey key = deriveKey(password, salt);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        byte[] decryptedData = cipher.doFinal(encrypted);
        return new String(decryptedData);
    }

    private SecretKey deriveKey(String password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    private byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }
}