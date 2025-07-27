package org.jboss.quickstarts.kitchensink.security;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.OAEPParameterSpec;
import java.util.Base64;

@Service
public class KeyPairService {
    
    private static final Logger logger = LoggerFactory.getLogger(KeyPairService.class);
    
    @Getter
    private KeyPair keyPair;
    
    @PostConstruct
    public void init() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        this.keyPair = keyPairGenerator.generateKeyPair();
        logger.info("RSA key pair initialized with 2048-bit key");
    }

    public String getPublicKeyBase64() {
        return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    }

    public String decryptPassword(String encryptedPassword) {
        try {
            logger.debug("Attempting to decrypt password. Encrypted length: {}", encryptedPassword.length());
            
            // Create OAEPParameterSpec to match Web Crypto API's RSA-OAEP with SHA-256
            OAEPParameterSpec oaepParams = new OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT
            );
            
            // Initialize cipher with specific OAEP parameters
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate(), oaepParams);
            
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedPassword);
            logger.debug("Decoded byte array length: {}", encryptedBytes.length);
            
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            String result = new String(decryptedBytes);
            logger.debug("Password decrypted successfully");
            return result;
        } catch (Exception e) {
            logger.error("Failed to decrypt password", e);
            throw new RuntimeException("Failed to decrypt password", e);
        }
    }
} 