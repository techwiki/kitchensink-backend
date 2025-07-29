package org.jboss.quickstarts.kitchensink.config;

import lombok.RequiredArgsConstructor;
import org.jboss.quickstarts.kitchensink.model.Member;
import org.jboss.quickstarts.kitchensink.model.Role;
import org.jboss.quickstarts.kitchensink.model.User;
import org.jboss.quickstarts.kitchensink.repository.MemberRepository;
import org.jboss.quickstarts.kitchensink.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {
    private static final Logger logger = LoggerFactory.getLogger(DataInitializer.class);

    private final UserRepository userRepository;
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${admin.default.password}")
    private String adminDefaultPassword;

    private static final String ADMIN_EMAIL = "admin@gmail.com";
    private static final String ADMIN_NAME = "Admin User";
    private static final String ADMIN_PHONE = "1234567890";

    @Override
    public void run(String... args) {
        // Check if admin user exists
        if (userRepository.findByEmail(ADMIN_EMAIL).isEmpty() && 
            memberRepository.findByEmail(ADMIN_EMAIL).isEmpty()) {
            
            logger.info("Creating admin user with default password");
            
            // Create admin member
            Member adminMember = new Member();
            adminMember.setName(ADMIN_NAME);
            adminMember.setEmail(ADMIN_EMAIL);
            adminMember.setPhoneNumber(ADMIN_PHONE);
            Member savedMember = memberRepository.save(adminMember);
            logger.debug("Created admin member with ID: {}", savedMember.getId());

            // Create admin user
            User adminUser = User.builder()
                    .email(ADMIN_EMAIL)
                    .password(passwordEncoder.encode(adminDefaultPassword))
                    .role(Role.ROLE_ADMIN)
                    .memberId(savedMember.getId())
                    .build();
            userRepository.save(adminUser);
            
            logger.info("Admin user created successfully");
        } else {
            logger.info("Admin user already exists, skipping creation");
        }
    }
} 