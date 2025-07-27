package org.jboss.quickstarts.kitchensink.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.jboss.quickstarts.kitchensink.model.Role;
import org.jboss.quickstarts.kitchensink.model.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class JwtServiceTest {

    private JwtService jwtService;
    private UserDetails userDetails;
    private final long jwtExpiration = 86400000; // 24 hours in milliseconds

    @BeforeEach
    void setUp() {
        jwtService = new JwtService();
        
        // Set up the service with test values
        ReflectionTestUtils.setField(jwtService, "secretKey", "test-secret-key");
        ReflectionTestUtils.setField(jwtService, "jwtExpiration", jwtExpiration);
        
        // Initialize the service
        jwtService.init();
        
        // Create test user
        userDetails = User.builder()
                .email("test@example.com")
                .password("password")
                .role(Role.ROLE_USER)
                .build();
    }

    @Test
    void init_ShouldInitializeSigningKey() {
        // Given
        JwtService newService = new JwtService();
        ReflectionTestUtils.setField(newService, "secretKey", "test-secret");
        ReflectionTestUtils.setField(newService, "jwtExpiration", 86400000L);
        
        // When
        newService.init();
        
        // Then
        SecretKey signingKey = (SecretKey) ReflectionTestUtils.getField(newService, "signingKey");
        assertNotNull(signingKey);
        assertEquals("HmacSHA256", signingKey.getAlgorithm());
    }

    @Test
    void generateToken_ShouldCreateValidJWT_WithDefaultClaims() {
        // When
        String token = jwtService.generateToken(userDetails);
        
        // Then
        assertNotNull(token);
        assertFalse(token.isEmpty());
        assertTrue(token.contains(".")); // JWT should have dots separating parts
        
        // Verify token structure (header.payload.signature)
        String[] tokenParts = token.split("\\.");
        assertEquals(3, tokenParts.length);
    }

    @Test
    void generateToken_ShouldCreateValidJWT_WithExtraClaims() {
        // Given
        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("customClaim", "customValue");
        extraClaims.put("memberId", "member123");
        
        // When
        String token = jwtService.generateToken(extraClaims, userDetails);
        
        // Then
        assertNotNull(token);
        assertFalse(token.isEmpty());
        
        // Verify custom claims are included
        Claims claims = extractAllClaimsForTesting(token);
        assertEquals("customValue", claims.get("customClaim"));
        assertEquals("member123", claims.get("memberId"));
    }

    @Test
    void generateToken_ShouldIncludeUserRole() {
        // When
        String token = jwtService.generateToken(userDetails);
        
        // Then
        Claims claims = extractAllClaimsForTesting(token);
        assertEquals("ROLE_USER", claims.get("role"));
    }

    @Test
    void generateToken_ShouldIncludeAdminRole() {
        // Given
        UserDetails adminUser = User.builder()
                .email("admin@example.com")
                .password("password")
                .role(Role.ROLE_ADMIN)
                .build();
        
        // When
        String token = jwtService.generateToken(adminUser);
        
        // Then
        Claims claims = extractAllClaimsForTesting(token);
        assertEquals("ROLE_ADMIN", claims.get("role"));
    }

    @Test
    void generateToken_ShouldSetCorrectSubject() {
        // When
        String token = jwtService.generateToken(userDetails);
        
        // Then
        Claims claims = extractAllClaimsForTesting(token);
        assertEquals("test@example.com", claims.getSubject());
    }

    @Test
    void generateToken_ShouldSetIssuedAtTime() {
        // Given
        Date beforeGeneration = new Date(System.currentTimeMillis());
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // When
        String token = jwtService.generateToken(userDetails);

        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Then
        Date afterGeneration = new Date(System.currentTimeMillis());
        Claims claims = extractAllClaimsForTesting(token);
        Date issuedAt = claims.getIssuedAt();
        
        assertNotNull(issuedAt);
        assertTrue(issuedAt.compareTo(beforeGeneration) > 0);
        assertTrue(issuedAt.compareTo(afterGeneration) < 0);
    }

    @Test
    void generateToken_ShouldSetExpirationTime() {
        // When
        String token = jwtService.generateToken(userDetails);

        // Then
        Claims claims = extractAllClaimsForTesting(token);
        Date expiration = claims.getExpiration();
        Date issuedAt = claims.getIssuedAt();
        
        assertNotNull(expiration);
        assertNotNull(issuedAt);
        
        long actualDuration = expiration.getTime() - issuedAt.getTime();
        assertEquals(jwtExpiration, actualDuration);
    }

    @Test
    void extractUsername_ShouldReturnCorrectUsername() {
        // Given
        String token = jwtService.generateToken(userDetails);
        
        // When
        String extractedUsername = jwtService.extractUsername(token);
        
        // Then
        assertEquals("test@example.com", extractedUsername);
    }

    @Test
    void extractClaim_ShouldReturnCorrectClaim() {
        // Given
        String token = jwtService.generateToken(userDetails);
        
        // When
        String subject = jwtService.extractClaim(token, Claims::getSubject);
        Date expiration = jwtService.extractClaim(token, Claims::getExpiration);
        
        // Then
        assertEquals("test@example.com", subject);
        assertNotNull(expiration);
    }

    @Test
    void extractClaim_ShouldReturnCustomClaim() {
        // Given
        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("customField", "customValue");
        String token = jwtService.generateToken(extraClaims, userDetails);
        
        // When
        String customClaim = jwtService.extractClaim(token, claims -> (String) claims.get("customField"));
        
        // Then
        assertEquals("customValue", customClaim);
    }

    @Test
    void isTokenValid_ShouldReturnTrue_ForValidToken() {
        // Given
        String token = jwtService.generateToken(userDetails);
        
        // When
        boolean isValid = jwtService.isTokenValid(token, userDetails);
        
        // Then
        assertTrue(isValid);
    }

    @Test
    void isTokenValid_ShouldReturnFalse_ForWrongUser() {
        // Given
        String token = jwtService.generateToken(userDetails);
        UserDetails differentUser = User.builder()
                .email("different@example.com")
                .password("password")
                .role(Role.ROLE_USER)
                .build();
        
        // When
        boolean isValid = jwtService.isTokenValid(token, differentUser);
        
        // Then
        assertFalse(isValid);
    }

    @Test
    void isTokenValid_ShouldThrowException_ForExpiredToken() {
        // Given - Create a service with very short expiration
        JwtService shortExpirationService = new JwtService();
        ReflectionTestUtils.setField(shortExpirationService, "secretKey", "test-secret-key");
        ReflectionTestUtils.setField(shortExpirationService, "jwtExpiration", 500L); // 500 millisecond
        shortExpirationService.init();
        
        String token = shortExpirationService.generateToken(userDetails);
        
        // Wait for token to expire
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        // When and Then
        assertThrows(ExpiredJwtException.class, () -> {shortExpirationService.isTokenValid(token, userDetails);});
    }

    @Test
    void extractUsername_ShouldThrowException_ForInvalidToken() {
        // Given
        String invalidToken = "invalid.jwt.token";
        
        // When & Then
        assertThrows(MalformedJwtException.class, () -> {
            jwtService.extractUsername(invalidToken);
        });
    }

    @Test
    void extractUsername_ShouldThrowException_ForTamperedToken() {
        // Given
        String token = jwtService.generateToken(userDetails);
        String tamperedToken = token.substring(0, token.length() - 5) + "tamper";
        
        // When & Then
        assertThrows(SignatureException.class, () -> {
            jwtService.extractUsername(tamperedToken);
        });
    }

    @Test
    void generateToken_ShouldCreateDifferentTokens_ForSameUser() {
        // When
        String token1 = jwtService.generateToken(userDetails);
        // Small delay to ensure different issued time
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        String token2 = jwtService.generateToken(userDetails);
        
        // Then
        assertNotEquals(token1, token2);
    }

    @Test
    void generateToken_ShouldUseDefaultRole_WhenUserRoleIsAvailable() {
        // Given - Create a user with a valid role (this is the normal case)
        UserDetails userWithRole = User.builder()
                .email("user@example.com")
                .password("password")
                .role(Role.ROLE_USER)
                .build();
        
        // When
        String token = jwtService.generateToken(userWithRole);
        
        // Then
        assertNotNull(token);
        Claims claims = extractAllClaimsForTesting(token);
        assertEquals("ROLE_USER", claims.get("role"));
    }

    @Test
    void isTokenValid_ShouldWork_WithMultipleValidations() {
        // Given
        String token = jwtService.generateToken(userDetails);
        
        // When & Then - Multiple validations should all return true
        assertTrue(jwtService.isTokenValid(token, userDetails));
        assertTrue(jwtService.isTokenValid(token, userDetails));
        assertTrue(jwtService.isTokenValid(token, userDetails));
    }

    @Test
    void extractClaim_ShouldWork_WithDifferentClaimTypes() {
        // Given
        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("stringClaim", "stringValue");
        extraClaims.put("numberClaim", 42);
        extraClaims.put("booleanClaim", true);
        
        String token = jwtService.generateToken(extraClaims, userDetails);
        
        // When
        String stringClaim = jwtService.extractClaim(token, claims -> (String) claims.get("stringClaim"));
        Integer numberClaim = jwtService.extractClaim(token, claims -> (Integer) claims.get("numberClaim"));
        Boolean booleanClaim = jwtService.extractClaim(token, claims -> (Boolean) claims.get("booleanClaim"));
        
        // Then
        assertEquals("stringValue", stringClaim);
        assertEquals(42, numberClaim);
        assertTrue(booleanClaim);
    }

    /**
     * Helper method to extract all claims for testing purposes
     * This bypasses the private method in the service
     */
    private Claims extractAllClaimsForTesting(String token) {
        SecretKey signingKey = (SecretKey) ReflectionTestUtils.getField(jwtService, "signingKey");
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
} 