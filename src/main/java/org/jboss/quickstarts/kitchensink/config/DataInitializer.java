package org.jboss.quickstarts.kitchensink.config;

import lombok.RequiredArgsConstructor;
import org.jboss.quickstarts.kitchensink.model.Member;
import org.jboss.quickstarts.kitchensink.model.Role;
import org.jboss.quickstarts.kitchensink.model.User;
import org.jboss.quickstarts.kitchensink.repository.MemberRepository;
import org.jboss.quickstarts.kitchensink.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${admin.default.password}")
    private String adminDefaultPassword;

    private static final String ADMIN_EMAIL = "admin@gmail.com";

    @Override
    public void run(String... args) {
        // Check if admin user exists
        if (userRepository.findByEmail(ADMIN_EMAIL).isEmpty() && 
            memberRepository.findByEmail(ADMIN_EMAIL).isEmpty()) {
            
            System.out.println("Creating admin user with default password. Please change it after first login.");
            
            // Create admin member
            Member adminMember = new Member();
            adminMember.setName("Admin User");
            adminMember.setEmail(ADMIN_EMAIL);
            adminMember.setPhoneNumber("1234567890");
            Member savedMember = memberRepository.save(adminMember);

            // Create admin user
            User adminUser = User.builder()
                    .email(ADMIN_EMAIL)
                    .password(passwordEncoder.encode(adminDefaultPassword))
                    .role(Role.ROLE_ADMIN)
                    .memberId(savedMember.getId())
                    .build();
            userRepository.save(adminUser);
            
            System.out.println("Admin user created successfully");
        } else {
            System.out.println("Admin user already exists, skipping creation");
        }
    }
} 