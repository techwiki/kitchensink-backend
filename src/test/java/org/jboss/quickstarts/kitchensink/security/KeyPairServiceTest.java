package org.jboss.quickstarts.kitchensink.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class KeyPairServiceTest {

    private KeyPairService keyPairService;
    
    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        keyPairService = new KeyPairService();
        keyPairService.init();
    }

    @Test
    void init_ShouldGenerateRSAKeyPair() throws NoSuchAlgorithmException {
        // Given
        KeyPairService newService = new KeyPairService();
        
        // When
        newService.init();
        
        // Then
        assertNotNull(newService.getKeyPair());
        assertEquals("RSA", newService.getKeyPair().getPublic().getAlgorithm());
        assertEquals("RSA", newService.getKeyPair().getPrivate().getAlgorithm());
    }

    @Test
    void init_ShouldGenerate2048BitKeys() throws NoSuchAlgorithmException {
        // Given
        KeyPairService newService = new KeyPairService();
        
        // When
        newService.init();
        
        // Then
        KeyPair keyPair = newService.getKeyPair();
        assertNotNull(keyPair);
        
        // RSA 2048-bit key should have modulus length of 2048 bits
        // We can verify this by checking the encoded key length
        byte[] publicKeyEncoded = keyPair.getPublic().getEncoded();
        byte[] privateKeyEncoded = keyPair.getPrivate().getEncoded();
        
        // 2048-bit RSA public key encoded should be around 294 bytes
        // 2048-bit RSA private key encoded should be around 1218 bytes
        assertTrue(publicKeyEncoded.length > 250 && publicKeyEncoded.length < 350);
        assertTrue(privateKeyEncoded.length > 1100 && privateKeyEncoded.length < 1300);
    }

    @Test
    void getPublicKeyBase64_ShouldReturnBase64EncodedPublicKey() {
        // When
        String publicKeyBase64 = keyPairService.getPublicKeyBase64();
        
        // Then
        assertNotNull(publicKeyBase64);
        assertFalse(publicKeyBase64.isEmpty());
        
        // Should be valid base64
        assertDoesNotThrow(() -> Base64.getDecoder().decode(publicKeyBase64));
        
        // Verify it matches the actual public key
        byte[] expectedBytes = keyPairService.getKeyPair().getPublic().getEncoded();
        String expectedBase64 = Base64.getEncoder().encodeToString(expectedBytes);
        assertEquals(expectedBase64, publicKeyBase64);
    }

    @Test
    void getPublicKeyBase64_ShouldReturnConsistentResult() {
        // When
        String publicKey1 = keyPairService.getPublicKeyBase64();
        String publicKey2 = keyPairService.getPublicKeyBase64();
        
        // Then
        assertEquals(publicKey1, publicKey2);
    }

    @Test
    void decryptPassword_ShouldDecryptValidEncryptedPassword() throws Exception {
        // Given
        String originalPassword = "TestPassword123!";
        String encryptedPassword = encryptPasswordForTesting(originalPassword);
        
        // When
        String decryptedPassword = keyPairService.decryptPassword(encryptedPassword);
        
        // Then
        assertEquals(originalPassword, decryptedPassword);
    }

    @Test
    void decryptPassword_ShouldHandleSpecialCharacters() throws Exception {
        // Given
        String originalPassword = "P@ssw0rd!@#$%^&*()";
        String encryptedPassword = encryptPasswordForTesting(originalPassword);
        
        // When
        String decryptedPassword = keyPairService.decryptPassword(encryptedPassword);
        
        // Then
        assertEquals(originalPassword, decryptedPassword);
    }

    @Test
    void decryptPassword_ShouldHandleUnicodeCharacters() throws Exception {
        // Given
        String originalPassword = "пароль123αβγ中文";
        String encryptedPassword = encryptPasswordForTesting(originalPassword);
        
        // When
        String decryptedPassword = keyPairService.decryptPassword(encryptedPassword);
        
        // Then
        assertEquals(originalPassword, decryptedPassword);
    }

    @Test
    void decryptPassword_ShouldHandleLongPasswords() throws Exception {
        // Given - Create a password that's close to but under the RSA encryption limit
        String originalPassword = "A".repeat(100); // 100 characters should be safe for 2048-bit RSA
        String encryptedPassword = encryptPasswordForTesting(originalPassword);
        
        // When
        String decryptedPassword = keyPairService.decryptPassword(encryptedPassword);
        
        // Then
        assertEquals(originalPassword, decryptedPassword);
    }

    @Test
    void decryptPassword_ShouldThrowRuntimeException_WhenInvalidBase64() {
        // Given
        String invalidBase64 = "invalid base64 string!@#";
        
        // When & Then
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            keyPairService.decryptPassword(invalidBase64);
        });
        
        assertEquals("Failed to decrypt password", exception.getMessage());
        assertNotNull(exception.getCause());
    }

    @Test
    void decryptPassword_ShouldThrowRuntimeException_WhenValidBase64ButInvalidEncryption() {
        // Given - Valid base64 but not encrypted with our key
        String validBase64ButWrongData = Base64.getEncoder().encodeToString("not encrypted data".getBytes());
        
        // When & Then
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            keyPairService.decryptPassword(validBase64ButWrongData);
        });
        
        assertEquals("Failed to decrypt password", exception.getMessage());
        assertNotNull(exception.getCause());
    }

    @Test
    void decryptPassword_ShouldThrowRuntimeException_WhenEmptyString() {
        // When & Then
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            keyPairService.decryptPassword("");
        });
        
        assertEquals("Failed to decrypt password", exception.getMessage());
    }

    @Test
    void decryptPassword_ShouldThrowRuntimeException_WhenNullInput() {
        // When & Then
        assertThrows(RuntimeException.class, () -> {
            keyPairService.decryptPassword(null);
        });
    }

    @Test
    void decryptPassword_ShouldHandleMultipleDecryptions() throws Exception {
        // Given
        String password1 = "Password1";
        String password2 = "Password2";
        String password3 = "Password3";
        
        String encrypted1 = encryptPasswordForTesting(password1);
        String encrypted2 = encryptPasswordForTesting(password2);
        String encrypted3 = encryptPasswordForTesting(password3);
        
        // When
        String decrypted1 = keyPairService.decryptPassword(encrypted1);
        String decrypted2 = keyPairService.decryptPassword(encrypted2);
        String decrypted3 = keyPairService.decryptPassword(encrypted3);
        
        // Then
        assertEquals(password1, decrypted1);
        assertEquals(password2, decrypted2);
        assertEquals(password3, decrypted3);
    }

    @Test
    void keyPair_ShouldBeAccessibleViaGetter() {
        // When
        KeyPair keyPair = keyPairService.getKeyPair();
        
        // Then
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublic());
        assertNotNull(keyPair.getPrivate());
    }

    @Test
    void encryptDecryptRoundTrip_ShouldWorkWithDifferentPasswordLengths() throws Exception {
        // Test with different password lengths
        String[] testPasswords = {
            "a",                    // 1 character
            "ab",                   // 2 characters
            "short",                // 5 characters
            "mediumlength",         // 12 characters
            "this is a longer password with spaces", // 38 characters
            "verylongpasswordwithlotsofcharactersbutnottoomanytocauseissues" // 63 characters
        };
        
        for (String password : testPasswords) {
            // Given
            String encrypted = encryptPasswordForTesting(password);
            
            // When
            String decrypted = keyPairService.decryptPassword(encrypted);
            
            // Then
            assertEquals(password, decrypted, "Failed for password: " + password);
        }
    }

    /**
     * Helper method to encrypt a password using the same OAEP parameters as the service
     * This simulates what the frontend would do
     */
    private String encryptPasswordForTesting(String password) throws Exception {
        OAEPParameterSpec oaepParams = new OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA256,
            PSource.PSpecified.DEFAULT
        );
        
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keyPairService.getKeyPair().getPublic(), oaepParams);
        
        byte[] encryptedBytes = cipher.doFinal(password.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
} 