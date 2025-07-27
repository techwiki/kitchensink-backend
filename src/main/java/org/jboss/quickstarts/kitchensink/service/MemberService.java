package org.jboss.quickstarts.kitchensink.service;

import jakarta.validation.ValidationException;
import lombok.RequiredArgsConstructor;
import org.jboss.quickstarts.kitchensink.dto.MemberDTO;
import org.jboss.quickstarts.kitchensink.model.Member;
import org.jboss.quickstarts.kitchensink.model.Role;
import org.jboss.quickstarts.kitchensink.model.User;
import org.jboss.quickstarts.kitchensink.repository.MemberRepository;
import org.jboss.quickstarts.kitchensink.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import org.springframework.security.crypto.password.PasswordEncoder;

@Service
@RequiredArgsConstructor
public class MemberService {
    private final MemberRepository memberRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public List<MemberDTO> findAll() {
        List<Member> members = memberRepository.findAllByOrderByNameAsc();
        return members.stream()
                .map(member -> {
                    Optional<User> userOpt = userRepository.findByMemberId(member.getId());
                    System.out.println("Finding role for member: " + member.getEmail());
                    System.out.println("User found: " + userOpt.isPresent());
                    Role role = userOpt
                            .map(user -> {
                                System.out.println("User role: " + user.getRole());
                                return user.getRole();
                            })
                            .orElse(Role.ROLE_USER);
                    return MemberDTO.fromMember(member, role);
                })
                .collect(Collectors.toList());
    }

    public Optional<MemberDTO> findById(String id) {
        return memberRepository.findById(id)
                .map(member -> {
                    Optional<User> userOpt = userRepository.findByMemberId(member.getId());
                    System.out.println("Finding role for member: " + member.getEmail());
                    System.out.println("User found: " + userOpt.isPresent());
                    Role role = userOpt
                            .map(user -> {
                                System.out.println("User role: " + user.getRole());
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

        // Check if a user account already exists for this email
        Optional<User> existingUser = userRepository.findByEmail(member.getEmail());
        if (existingUser.isEmpty()) {
            // Create a new user account with a default password
            User user = User.builder()
                    .email(member.getEmail())
                    .password(passwordEncoder.encode("changeme123")) // Default password that should be changed on first login
                    .role(Role.ROLE_USER)
                    .memberId(savedMember.getId())
                    .build();
            userRepository.save(user);
        } else {
            // Update existing user's memberId
            User user = existingUser.get();
            user.setMemberId(savedMember.getId());
            userRepository.save(user);
        }

        return savedMember;
    }

    @Transactional
    public Member update(Member member) {
        if (member.getId() == null) {
            throw new ValidationException("Member ID cannot be null");
        }

        // Check if member exists
        Member existingMember = memberRepository.findById(member.getId())
                .orElseThrow(() -> new ValidationException("Member not found"));

        // Check if email is being changed and if new email already exists
        if (!existingMember.getEmail().equals(member.getEmail())) {
            memberRepository.findByEmail(member.getEmail()).ifPresent(m -> {
                throw new ValidationException("Email already exists");
            });
        }

        return memberRepository.save(member);
    }

    @Transactional
    public MemberDTO updateRole(String memberId, Role newRole) {
        Member member = memberRepository.findById(memberId)
                .orElseThrow(() -> new ValidationException("Member not found"));

        User user = userRepository.findByMemberId(memberId)
                .orElseThrow(() -> new ValidationException("User account not found"));

        user.setRole(newRole);
        userRepository.save(user);

        return MemberDTO.fromMember(member, newRole);
    }

    @Transactional
    public void delete(String id) {
        memberRepository.deleteById(id);
    }
} 