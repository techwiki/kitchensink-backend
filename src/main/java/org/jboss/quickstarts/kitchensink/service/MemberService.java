package org.jboss.quickstarts.kitchensink.service;

import jakarta.validation.ValidationException;
import lombok.RequiredArgsConstructor;
import org.jboss.quickstarts.kitchensink.dto.MemberDTO;
import org.jboss.quickstarts.kitchensink.dto.RegisterRequest;
import org.jboss.quickstarts.kitchensink.model.Member;
import org.jboss.quickstarts.kitchensink.model.Role;
import org.jboss.quickstarts.kitchensink.model.User;
import org.jboss.quickstarts.kitchensink.repository.MemberRepository;
import org.jboss.quickstarts.kitchensink.repository.UserRepository;
import org.jboss.quickstarts.kitchensink.security.KeyPairService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class MemberService {
    private static final Logger logger = LoggerFactory.getLogger(MemberService.class);

    private final MemberRepository memberRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final KeyPairService keyPairService;

    public static class MemberNotFoundException extends RuntimeException {
        public MemberNotFoundException(String message) {
            super(message);
        }
    }

    private Role resolveRole(Member member) {
        logger.debug("Resolving role for member: {}", member.getEmail());
        Optional<User> userOpt = userRepository.findByEmail(member.getEmail());
        logger.debug("User found status: {}", userOpt.isPresent());
        
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            logger.debug("User role resolved: {}", user.getRole());
            return user.getRole();
        }
        return Role.ROLE_USER;
    }

    public List<MemberDTO> findAll() {
        return memberRepository.findAll().stream()
                .map(member -> {
                    logger.debug("Resolving role for member: {}", member.getEmail());
                    Optional<User> userOpt = userRepository.findByEmail(member.getEmail());
                    logger.debug("User found status: {}", userOpt.isPresent());
                    
                    Role role = Role.ROLE_USER;
                    if (userOpt.isPresent()) {
                        User user = userOpt.get();
                        role = user.getRole();
                        logger.debug("User role resolved: {}", role);
                    }
                    
                    return MemberDTO.fromMember(member, role);
                })
                .collect(Collectors.toList());
    }

    public Optional<MemberDTO> findById(String id) {
        return memberRepository.findById(id)
                .map(member -> {
                    Optional<User> userOpt = userRepository.findByMemberId(member.getId());
                    logger.debug("Finding role for member: {}", member.getEmail());
                    logger.debug("User found status: {}", userOpt.isPresent());
                    Role role = userOpt
                            .map(user -> {
                                logger.debug("User role: {}", user.getRole());
                                return user.getRole();
                            })
                            .orElse(Role.ROLE_USER);
                    return MemberDTO.fromMember(member, role);
                });
    }

    @Transactional
    public Member save(Member member) {
        if (memberRepository.findByEmail(member.getEmail()).isPresent()) {
            throw new ValidationException("Email already exists");
        }
        Member savedMember = memberRepository.save(member);
        return savedMember;
    }

    @Transactional
    public Member update(Member member) {
        if (member.getId() == null) {
            throw new ValidationException("Member ID cannot be null");
        }

        // Check if member exists
        Member existingMember = memberRepository.findById(member.getId())
                .orElseThrow(() -> new MemberNotFoundException("Member not found"));

        // Email cannot be updated
        if (!existingMember.getEmail().equals(member.getEmail())) {
            throw new ValidationException("Email cannot be updated");
        }

        // Update allowed fields
        existingMember.setName(member.getName());
        existingMember.setPhoneNumber(member.getPhoneNumber());

        return memberRepository.save(existingMember);
    }

    @Transactional
    public MemberDTO updateRole(String memberId, Role newRole) {
        Member member = memberRepository.findById(memberId)
                .orElseThrow(() -> new MemberNotFoundException("Member not found"));

        User user = userRepository.findByMemberId(memberId)
                .orElseThrow(() -> new ValidationException("User account not found"));

        user.setRole(newRole);
        userRepository.save(user);

        return MemberDTO.fromMember(member, newRole);
    }

    @Transactional
    public MemberDTO createMemberWithUser(RegisterRequest request) {
        if (memberRepository.findByEmail(request.email()).isPresent()) {
            throw new ValidationException("Email already exists");
        }

        // Check if user already exists
        if (userRepository.findByEmail(request.email()).isPresent()) {
            throw new ValidationException("User account already exists");
        }

        // Create and save member
        Member member = Member.builder()
                .name(request.name())
                .email(request.email())
                .phoneNumber(request.phoneNumber())
                .build();
        Member savedMember = memberRepository.save(member);
        logger.debug("Created member with ID: {}", savedMember.getId());

        // Create user account with the provided password
        String decryptedPassword = keyPairService.decryptPassword(request.password());
        User user = User.builder()
                .email(request.email())
                .password(passwordEncoder.encode(decryptedPassword))
                .role(Role.ROLE_USER)
                .memberId(savedMember.getId())
                .build();
        userRepository.save(user);
        logger.debug("Created user account for member ID: {}", savedMember.getId());

        return MemberDTO.fromMember(savedMember, Role.ROLE_USER);
    }

    @Transactional
    public void delete(String id) {
        if (!memberRepository.existsById(id)) {
            throw new MemberNotFoundException("Member not found");
        }
        
        // Delete associated user first
        userRepository.findByMemberId(id).ifPresent(user -> {
            logger.debug("Deleting associated user with email: {}", user.getEmail());
            userRepository.delete(user);
        });

        // Then delete the member
        logger.debug("Deleting member with ID: {}", id);
        memberRepository.deleteById(id);
    }
} 