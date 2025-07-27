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
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final MemberService memberService;
    private final KeyPairService keyPairService;

    public AuthResponse register(RegisterRequest request) {
        // TEMPORARY: Skip decryption for debugging
        System.out.println("TEMPORARY: Skipping decryption for debugging");
        String decryptedPassword = request.password(); // Use password as-is temporarily
        
        // Create member first
        Member member = new Member();
        member.setName(request.name());
        member.setEmail(request.email());
        member.setPhoneNumber(request.phoneNumber());
        Member savedMember = memberService.save(member);

        // Create user account with decrypted and then hashed password
        var user = User.builder()
                .email(request.email())
                .password(passwordEncoder.encode(decryptedPassword))
                .role(Role.ROLE_USER)
                .memberId(savedMember.getId())
                .build();
        userRepository.save(user);

        var token = jwtService.generateToken(user);
        return AuthResponse.builder()
                .token(token)
                .build();
    }

    public AuthResponse authenticate(AuthRequest request) {
        // TEMPORARY: Skip decryption for debugging
        System.out.println("TEMPORARY: Skipping decryption for debugging");
        String decryptedPassword = request.password(); // Use password as-is temporarily
        
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.email(),
                        decryptedPassword
                )
        );

        var user = userRepository.findByEmail(request.email())
                .orElseThrow();
        var token = jwtService.generateToken(user);
        return AuthResponse.builder()
                .token(token)
                .build();
    }
} 