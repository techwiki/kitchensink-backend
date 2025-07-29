package org.jboss.quickstarts.kitchensink.service;

import lombok.RequiredArgsConstructor;
import org.jboss.quickstarts.kitchensink.dto.AuthRequest;
import org.jboss.quickstarts.kitchensink.dto.AuthResponse;
import org.jboss.quickstarts.kitchensink.dto.RegisterRequest;
import org.jboss.quickstarts.kitchensink.model.Member;
import org.jboss.quickstarts.kitchensink.model.Role;
import org.jboss.quickstarts.kitchensink.model.User;
import org.jboss.quickstarts.kitchensink.repository.UserRepository;
import org.jboss.quickstarts.kitchensink.security.JwtService;
import org.jboss.quickstarts.kitchensink.security.KeyPairService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import jakarta.validation.ValidationException;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationService.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final MemberService memberService;
    private final KeyPairService keyPairService;

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        logger.info("Processing registration request for email: {}", request.email());

        // Check if user already exists
        if (userRepository.findByEmail(request.email()).isPresent()) {
            logger.warn("Registration failed: Email {} already exists", request.email());
            throw new ValidationException("Email already exists");
        }

        try {
            String decryptedPassword = keyPairService.decryptPassword(request.password());

            // Create member first
            Member member = Member.builder()
                    .name(request.name())
                    .email(request.email())
                    .phoneNumber(request.phoneNumber())
                    .build();
            Member savedMember = memberService.save(member);
            logger.debug("Created member with ID: {}", savedMember.getId());

            // Create user account with decrypted and then hashed password
            var user = User.builder()
                    .email(request.email())
                    .password(passwordEncoder.encode(decryptedPassword))
                    .role(Role.ROLE_USER)
                    .memberId(savedMember.getId())
                    .build();
            userRepository.save(user);
            logger.debug("Created user account for member ID: {}", savedMember.getId());

            var token = jwtService.generateToken(user);
            logger.info("Registration completed successfully for email: {}", request.email());
            return AuthResponse.builder()
                    .token(token)
                    .build();
        } catch (Exception e) {
            logger.error("Registration failed for email: {}", request.email(), e);
            throw new ValidationException("Registration failed: " + e.getMessage());
        }
    }

    public AuthResponse authenticate(AuthRequest request) {
        logger.info("Processing authentication request for email: {}", request.email());
        String decryptedPassword = keyPairService.decryptPassword(request.password());

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.email(),
                        decryptedPassword
                )
        );

        var user = userRepository.findByEmail(request.email()).orElseThrow();
        var token = jwtService.generateToken(user);
        logger.info("Authentication successful for email: {}", request.email());
        return AuthResponse
                .builder()
                .token(token)
                .build();
    }
} 