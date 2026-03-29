package com.networkmonitor.secure_network_monitor;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.FileOutputStream;
import java.security.KeyStore;

/**
 * Utility to generate the test-keystore.p12 file for test environment.
 * Run this once to create the keystore, then delete this file.
 */
public class GenerateTestKeystore {
    public static void main(String[] args) throws Exception {
        // Generate a 256-bit AES key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();

        // Create a PKCS12 keystore
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null); // Initialize empty keystore

        // Store the secret key
        KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(secretKey);
        KeyStore.ProtectionParameter protParam = 
            new KeyStore.PasswordProtection("testkeystorepass".toCharArray());
        keyStore.setEntry("test-key", skEntry, protParam);

        // Write to file
        try (FileOutputStream fos = new FileOutputStream("test-keystore.p12")) {
            keyStore.store(fos, "testkeystorepass".toCharArray());
        }

        System.out.println("test-keystore.p12 created successfully!");
    }
}
