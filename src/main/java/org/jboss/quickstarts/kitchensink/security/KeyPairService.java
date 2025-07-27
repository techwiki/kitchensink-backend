package org.jboss.quickstarts.kitchensink.security;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import java.security.*;
import java.util.Base64;

@Service
public class KeyPairService {
    
    @Getter
    private KeyPair keyPair;
    
    @PostConstruct
    public void init() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // Use 2048 bits for good security
        this.keyPair = keyPairGenerator.generateKeyPair();
    }

    public String getPublicKeyBase64() {
        return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    }

    public String decryptPassword(String encryptedPassword) {
        try {
            System.out.println("Attempting to decrypt password. Encrypted length: " + encryptedPassword.length());
            System.out.println("Encrypted password (first 50 chars): " + encryptedPassword.substring(0, Math.min(50, encryptedPassword.length())));
            
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedPassword);
            System.out.println("Decoded byte array length: " + encryptedBytes.length);
            
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            String result = new String(decryptedBytes);
            System.out.println("Successfully decrypted password");
            return result;
        } catch (Exception e) {
            System.err.println("Decryption failed: " + e.getMessage());
            throw new RuntimeException("Failed to decrypt password", e);
        }
    }
} 