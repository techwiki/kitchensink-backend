package org.jboss.quickstarts.kitchensink.service;

import org.jboss.quickstarts.kitchensink.dto.AuthRequest;
import org.jboss.quickstarts.kitchensink.dto.AuthResponse;
import org.jboss.quickstarts.kitchensink.dto.RegisterRequest;
import org.jboss.quickstarts.kitchensink.model.Member;
import org.jboss.quickstarts.kitchensink.model.Role;
import org.jboss.quickstarts.kitchensink.model.User;
import org.jboss.quickstarts.kitchensink.repository.MemberRepository;
import org.jboss.quickstarts.kitchensink.repository.UserRepository;
import org.jboss.quickstarts.kitchensink.security.JwtService;
import org.jboss.quickstarts.kitchensink.security.KeyPairService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.Cipher;
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.util.Base64;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthenticationServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private MemberRepository memberRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    private JwtService jwtService; // Real instance

    @Mock
    private AuthenticationManager authenticationManager;

    private MemberService memberService; // Real instance

    private KeyPairService keyPairService; // Real instance

    private AuthenticationService authenticationService; // Real instance

    private RegisterRequest registerRequest;
    private AuthRequest authRequest;
    private Member member;
    private User user;

    @BeforeEach
    void setUp() throws Exception {
        // Set up real JwtService instance
        jwtService = new JwtService();
        ReflectionTestUtils.setField(jwtService, "secretKey", "test-secret-key");
        ReflectionTestUtils.setField(jwtService, "jwtExpiration", 86400000L);
        jwtService.init();
        
        // Set up real KeyPairService instance
        keyPairService = new KeyPairService();
        keyPairService.init();
        
        // Set up real MemberService instance with mocked repositories
        memberService = new MemberService(memberRepository, userRepository, passwordEncoder);
        
        // Set up real AuthenticationService instance
        authenticationService = new AuthenticationService(
                userRepository,
                passwordEncoder,
                jwtService,
                authenticationManager,
                memberService,
                keyPairService
        );

        registerRequest = new RegisterRequest(
                "test@example.com",
                "encryptedPassword123",
                "John Doe",
                "1234567890"
        );

        authRequest = new AuthRequest("test@example.com", "encryptedPassword123");

        member = new Member();
        member.setId("member123");
        member.setName("John Doe");
        member.setEmail("test@example.com");
        member.setPhoneNumber("1234567890");

        user = User.builder()
                .id("user123")
                .email("test@example.com")
                .password("hashedPassword")
                .role(Role.ROLE_USER)
                .memberId("member123")
                .build();
    }

    @Test
    void register_ShouldCreateMemberAndUserAndReturnToken() throws Exception {
        // Given
        String plainPassword = "plainPassword123";
        String encryptedPassword = encryptPasswordForTesting(plainPassword);
        String hashedPassword = "hashedPassword";

        // Update the request to use real encrypted password
        RegisterRequest testRequest = new RegisterRequest(
                "test@example.com",
                encryptedPassword,
                "John Doe",
                "1234567890"
        );

        when(memberRepository.findByEmail("test@example.com")).thenReturn(Optional.empty());
        when(memberRepository.save(any(Member.class))).thenReturn(member);
        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("changeme123")).thenReturn("hashedDefaultPassword");
        when(passwordEncoder.encode(plainPassword)).thenReturn(hashedPassword);
        when(userRepository.save(any(User.class))).thenReturn(user);

        // When
        AuthResponse response = authenticationService.register(testRequest);

        // Then
        assertNotNull(response);
        assertNotNull(response.token());
        assertFalse(response.token().isEmpty());

        // Verify member creation
        ArgumentCaptor<Member> memberCaptor = ArgumentCaptor.forClass(Member.class);
        verify(memberRepository).save(memberCaptor.capture());
        Member capturedMember = memberCaptor.getValue();
        assertEquals("John Doe", capturedMember.getName());
        assertEquals("test@example.com", capturedMember.getEmail());
        assertEquals("1234567890", capturedMember.getPhoneNumber());

        // Verify user creation (both from MemberService and AuthenticationService)
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository, times(2)).save(userCaptor.capture());
        
        // Check the user created by AuthenticationService
        User authUser = userCaptor.getAllValues().get(1);
        assertEquals("test@example.com", authUser.getEmail());
        assertEquals(hashedPassword, authUser.getPassword());
        assertEquals(Role.ROLE_USER, authUser.getRole());
        assertEquals("member123", authUser.getMemberId());

        verify(passwordEncoder).encode(plainPassword);
    }

    @Test
    void register_ShouldDecryptPasswordBeforeHashing() throws Exception {
        // Given
        String plainPassword = "plainPassword123";
        String encryptedPassword = encryptPasswordForTesting(plainPassword);
        String hashedPassword = "hashedPassword";

        RegisterRequest testRequest = new RegisterRequest(
                "test@example.com",
                encryptedPassword,
                "John Doe",
                "1234567890"
        );

        when(memberRepository.findByEmail(anyString())).thenReturn(Optional.empty());
        when(memberRepository.save(any(Member.class))).thenReturn(member);
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());
        when(passwordEncoder.encode("changeme123")).thenReturn("hashedDefaultPassword");
        when(passwordEncoder.encode(plainPassword)).thenReturn(hashedPassword);
        when(userRepository.save(any(User.class))).thenReturn(user);

        // When
        authenticationService.register(testRequest);

        // Then
        verify(passwordEncoder).encode(plainPassword);
    }

    @Test
    void authenticate_ShouldAuthenticateUserAndReturnToken() throws Exception {
        // Given
        String plainPassword = "plainPassword123";
        String encryptedPassword = encryptPasswordForTesting(plainPassword);

        AuthRequest testRequest = new AuthRequest("test@example.com", encryptedPassword);

        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(user));

        // When
        AuthResponse response = authenticationService.authenticate(testRequest);

        // Then
        assertNotNull(response);
        assertNotNull(response.token());
        assertFalse(response.token().isEmpty());

        // Verify authentication was called with decrypted password
        ArgumentCaptor<UsernamePasswordAuthenticationToken> authCaptor = 
                ArgumentCaptor.forClass(UsernamePasswordAuthenticationToken.class);
        verify(authenticationManager).authenticate(authCaptor.capture());
        UsernamePasswordAuthenticationToken capturedAuth = authCaptor.getValue();
        assertEquals("test@example.com", capturedAuth.getName());
        assertEquals(plainPassword, capturedAuth.getCredentials());

        verify(userRepository).findByEmail("test@example.com");
    }

    @Test
    void authenticate_ShouldThrowException_WhenUserNotFound() throws Exception {
        // Given
        String plainPassword = "plainPassword123";
        String encryptedPassword = encryptPasswordForTesting(plainPassword);
        AuthRequest testRequest = new AuthRequest("test@example.com", encryptedPassword);

        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.empty());

        // When & Then
        assertThrows(RuntimeException.class, () -> {
            authenticationService.authenticate(testRequest);
        });

        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(userRepository).findByEmail("test@example.com");
    }

    @Test
    void authenticate_ShouldDecryptPasswordBeforeAuthentication() throws Exception {
        // Given
        String plainPassword = "plainPassword123";
        String encryptedPassword = encryptPasswordForTesting(plainPassword);
        AuthRequest testRequest = new AuthRequest("test@example.com", encryptedPassword);

        when(userRepository.findByEmail(anyString())).thenReturn(Optional.of(user));

        // When
        authenticationService.authenticate(testRequest);

        // Then
        ArgumentCaptor<UsernamePasswordAuthenticationToken> authCaptor = 
                ArgumentCaptor.forClass(UsernamePasswordAuthenticationToken.class);
        verify(authenticationManager).authenticate(authCaptor.capture());
        assertEquals(plainPassword, authCaptor.getValue().getCredentials());
    }

    @Test
    void register_ShouldSetCorrectUserRole() throws Exception {
        // Given
        String plainPassword = "plainPassword";
        String encryptedPassword = encryptPasswordForTesting(plainPassword);
        RegisterRequest testRequest = new RegisterRequest(
                "test@example.com",
                encryptedPassword,
                "John Doe",
                "1234567890"
        );

        when(memberRepository.findByEmail(anyString())).thenReturn(Optional.empty());
        when(memberRepository.save(any(Member.class))).thenReturn(member);
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());
        when(passwordEncoder.encode("changeme123")).thenReturn("hashedDefaultPassword");
        when(passwordEncoder.encode(plainPassword)).thenReturn("hashedPassword");
        when(userRepository.save(any(User.class))).thenReturn(user);

        // When
        authenticationService.register(testRequest);

        // Then
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository, times(2)).save(userCaptor.capture());
        
        // Check the user created by AuthenticationService (second call)
        User authUser = userCaptor.getAllValues().get(1);
        assertEquals(Role.ROLE_USER, authUser.getRole());
    }

    @Test
    void register_ShouldLinkUserToMember() throws Exception {
        // Given
        String plainPassword = "plainPassword";
        String encryptedPassword = encryptPasswordForTesting(plainPassword);
        RegisterRequest testRequest = new RegisterRequest(
                "test@example.com",
                encryptedPassword,
                "John Doe",
                "1234567890"
        );

        when(memberRepository.findByEmail(anyString())).thenReturn(Optional.empty());
        when(memberRepository.save(any(Member.class))).thenReturn(member);
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());
        when(passwordEncoder.encode("changeme123")).thenReturn("hashedDefaultPassword");
        when(passwordEncoder.encode(plainPassword)).thenReturn("hashedPassword");
        when(userRepository.save(any(User.class))).thenReturn(user);

        // When
        authenticationService.register(testRequest);

        // Then
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository, times(2)).save(userCaptor.capture());
        
        // Check the user created by AuthenticationService (second call)
        User authUser = userCaptor.getAllValues().get(1);
        assertEquals(member.getId(), authUser.getMemberId());
    }

    @Test
    void register_ShouldGenerateValidJwtToken() throws Exception {
        // Given
        String plainPassword = "plainPassword";
        String encryptedPassword = encryptPasswordForTesting(plainPassword);
        RegisterRequest testRequest = new RegisterRequest(
                "test@example.com",
                encryptedPassword,
                "John Doe",
                "1234567890"
        );

        when(memberRepository.findByEmail(anyString())).thenReturn(Optional.empty());
        when(memberRepository.save(any(Member.class))).thenReturn(member);
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());
        when(passwordEncoder.encode("changeme123")).thenReturn("hashedDefaultPassword");
        when(passwordEncoder.encode(plainPassword)).thenReturn("hashedPassword");
        when(userRepository.save(any(User.class))).thenReturn(user);

        // When
        AuthResponse response = authenticationService.register(testRequest);

        // Then
        assertNotNull(response.token());
        assertTrue(response.token().contains(".")); // JWT should have dots
        
        // Verify JWT contains expected username
        String extractedUsername = jwtService.extractUsername(response.token());
        assertEquals("test@example.com", extractedUsername);
    }

    @Test
    void authenticate_ShouldGenerateValidJwtToken() throws Exception {
        // Given
        String plainPassword = "plainPassword";
        String encryptedPassword = encryptPasswordForTesting(plainPassword);
        AuthRequest testRequest = new AuthRequest("test@example.com", encryptedPassword);

        when(userRepository.findByEmail(anyString())).thenReturn(Optional.of(user));

        // When
        AuthResponse response = authenticationService.authenticate(testRequest);

        // Then
        assertNotNull(response.token());
        assertTrue(response.token().contains(".")); // JWT should have dots
        
        // Verify JWT contains expected username
        String extractedUsername = jwtService.extractUsername(response.token());
        assertEquals("test@example.com", extractedUsername);
        
        // Verify token is valid for the user
        assertTrue(jwtService.isTokenValid(response.token(), user));
    }

    /**
     * Helper method to encrypt a password using the same OAEP parameters as KeyPairService
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