package org.jboss.quickstarts.kitchensink.service;

import jakarta.validation.ValidationException;
import lombok.RequiredArgsConstructor;
import org.jboss.quickstarts.kitchensink.model.Member;
import org.jboss.quickstarts.kitchensink.repository.MemberRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class MemberService {
    private final MemberRepository repository;

    public List<Member> findAll() {
        return repository.findAllByOrderByNameAsc();
    }

    public Optional<Member> findById(String id) {
        return repository.findById(id);
    }

    @Transactional
    public Member save(Member member) {
        if (repository.findByEmail(member.getEmail()).isPresent()) {
            throw new ValidationException("Email already exists");
        }
        return repository.save(member);
    }

    @Transactional
    public Member update(Member member) {
        if (member.getId() == null) {
            throw new ValidationException("Member ID cannot be null");
        }

        // Check if member exists
        Member existingMember = repository.findById(member.getId())
                .orElseThrow(() -> new ValidationException("Member not found"));

        // Check if email is being changed and if new email already exists
        if (!existingMember.getEmail().equals(member.getEmail())) {
            repository.findByEmail(member.getEmail()).ifPresent(m -> {
                throw new ValidationException("Email already exists");
            });
        }

        return repository.save(member);
    }

    @Transactional
    public void delete(String id) {
        repository.deleteById(id);
    }
} 