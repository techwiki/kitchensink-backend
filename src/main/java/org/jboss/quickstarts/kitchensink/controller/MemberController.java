package org.jboss.quickstarts.kitchensink.controller;

import jakarta.validation.Valid;
import jakarta.validation.ValidationException;
import lombok.RequiredArgsConstructor;
import org.jboss.quickstarts.kitchensink.dto.RegisterRequest;
import org.jboss.quickstarts.kitchensink.dto.RoleUpdateRequest;
import org.jboss.quickstarts.kitchensink.model.Member;
import org.jboss.quickstarts.kitchensink.model.Role;
import org.jboss.quickstarts.kitchensink.model.User;
import org.jboss.quickstarts.kitchensink.service.MemberService;
import org.jboss.quickstarts.kitchensink.service.MemberService.MemberNotFoundException;
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
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
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
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Member not found"));
    }

    @PostMapping
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<MemberDTO> createMember(@Valid @RequestBody RegisterRequest request) {
        try {
            MemberDTO savedMember = memberService.createMemberWithUser(request);
            return ResponseEntity.status(HttpStatus.CREATED).body(savedMember);
        } catch (ValidationException e) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, e.getMessage());
        }
    }

    @PutMapping("/{id}")
    public ResponseEntity<MemberDTO> updateMember(
            @PathVariable String id,
            @Valid @RequestBody MemberDTO memberDTO,
            @AuthenticationPrincipal User user
    ) {
        if (!user.getRole().equals(Role.ROLE_ADMIN) && !user.getMemberId().equals(id)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Access denied");
        }
        try {
            Member member = memberDTO.toMember();
            member.setId(id);
            Member updatedMember = memberService.update(member);
            return ResponseEntity.ok(MemberDTO.fromMember(updatedMember, memberDTO.getRole()));
        } catch (ValidationException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        } catch (MemberNotFoundException e) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage());
        }
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<Void> deleteMember(@PathVariable String id) {
        try {
            memberService.delete(id);
            return ResponseEntity.noContent().build();
        } catch (MemberNotFoundException e) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage());
        }
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
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<MemberDTO> updateMemberRole(
            @PathVariable String id,
            @RequestBody RoleUpdateRequest request
    ) {
        try {
            return ResponseEntity.ok(memberService.updateRole(id, request.role()));
        } catch (ValidationException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        } catch (MemberNotFoundException e) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage());
        }
    }
} 