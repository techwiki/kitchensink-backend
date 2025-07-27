package org.jboss.quickstarts.kitchensink.controller;

import jakarta.validation.Valid;
import jakarta.validation.ValidationException;
import lombok.RequiredArgsConstructor;
import org.jboss.quickstarts.kitchensink.dto.RoleUpdateRequest;
import org.jboss.quickstarts.kitchensink.model.Member;
import org.jboss.quickstarts.kitchensink.model.Role;
import org.jboss.quickstarts.kitchensink.model.User;
import org.jboss.quickstarts.kitchensink.service.MemberService;
import org.jboss.quickstarts.kitchensink.dto.MemberDTO;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@RestController
@RequestMapping("/api/members")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:3000")
public class MemberController {
    private final MemberService memberService;

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<MemberDTO>> getAllMembers() {
        return ResponseEntity.ok(memberService.findAll());
    }

    @GetMapping("/{id}")
    public ResponseEntity<MemberDTO> getMember(@PathVariable String id, @AuthenticationPrincipal User user) {
        if (!user.getRole().equals(Role.ROLE_ADMIN) && !user.getMemberId().equals(id)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Access denied");
        }
        return memberService.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Member> createMember(@Valid @RequestBody Member member) {
        try {
            Member savedMember = memberService.save(member);
            return ResponseEntity.status(HttpStatus.CREATED).body(savedMember);
        } catch (ValidationException e) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, e.getMessage());
        }
    }

    @PutMapping("/{id}")
    public ResponseEntity<Member> updateMember(
            @PathVariable String id,
            @Valid @RequestBody Member member,
            @AuthenticationPrincipal User user
    ) {
        if (!user.getRole().equals(Role.ROLE_ADMIN) && !user.getMemberId().equals(id)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Access denied");
        }
        try {
            member.setId(id);
            Member updatedMember = memberService.update(member);
            return ResponseEntity.ok(updatedMember);
        } catch (ValidationException e) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, e.getMessage());
        }
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteMember(@PathVariable String id) {
        memberService.delete(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/me")
    public ResponseEntity<MemberDTO> getCurrentMember(@AuthenticationPrincipal User user) {
        if (user.getMemberId() == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "No member profile found");
        }
        return memberService.findById(user.getMemberId())
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PatchMapping("/{id}/role")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<MemberDTO> updateMemberRole(
            @PathVariable String id,
            @RequestBody RoleUpdateRequest request
    ) {
        try {
            return ResponseEntity.ok(memberService.updateRole(id, request.role()));
        } catch (ValidationException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }
} 