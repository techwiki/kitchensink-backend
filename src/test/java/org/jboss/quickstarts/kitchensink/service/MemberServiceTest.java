package org.jboss.quickstarts.kitchensink.service;

import jakarta.validation.ValidationException;
import org.jboss.quickstarts.kitchensink.dto.MemberDTO;
import org.jboss.quickstarts.kitchensink.model.Member;
import org.jboss.quickstarts.kitchensink.model.Role;
import org.jboss.quickstarts.kitchensink.model.User;
import org.jboss.quickstarts.kitchensink.repository.MemberRepository;
import org.jboss.quickstarts.kitchensink.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class MemberServiceTest {

    @Mock
    private MemberRepository memberRepository;

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private MemberService memberService;

    private Member member;
    private User user;
    private MemberDTO memberDTO;

    @BeforeEach
    void setUp() {
        member = new Member();
        member.setId("member123");
        member.setName("John Doe");
        member.setEmail("john@example.com");
        member.setPhoneNumber("1234567890");

        user = User.builder()
                .id("user123")
                .email("john@example.com")
                .password("hashedPassword")
                .role(Role.ROLE_USER)
                .memberId("member123")
                .build();

        memberDTO = MemberDTO.builder()
                .id("member123")
                .name("John Doe")
                .email("john@example.com")
                .phoneNumber("1234567890")
                .role(Role.ROLE_USER)
                .build();
    }

    @Test
    void findAll_ShouldReturnAllMembersWithRoles() {
        // Given
        Member member2 = new Member();
        member2.setId("member456");
        member2.setName("Jane Smith");
        member2.setEmail("jane@example.com");
        member2.setPhoneNumber("0987654321");

        User user2 = User.builder()
                .id("user456")
                .email("jane@example.com")
                .role(Role.ROLE_ADMIN)
                .memberId("member456")
                .build();

        when(memberRepository.findAll()).thenReturn(Arrays.asList(member, member2));
        when(userRepository.findByEmail("john@example.com")).thenReturn(Optional.of(user));
        when(userRepository.findByEmail("jane@example.com")).thenReturn(Optional.of(user2));

        // When
        List<MemberDTO> result = memberService.findAll();

        // Then
        assertEquals(2, result.size());

        MemberDTO dto1 = result.get(0);
        assertEquals("member123", dto1.getId());
        assertEquals("John Doe", dto1.getName());
        assertEquals("john@example.com", dto1.getEmail());
        assertEquals("1234567890", dto1.getPhoneNumber());
        assertEquals(Role.ROLE_USER, dto1.getRole());

        MemberDTO dto2 = result.get(1);
        assertEquals("member456", dto2.getId());
        assertEquals("Jane Smith", dto2.getName());
        assertEquals("jane@example.com", dto2.getEmail());
        assertEquals("0987654321", dto2.getPhoneNumber());
        assertEquals(Role.ROLE_ADMIN, dto2.getRole());

        verify(memberRepository).findAll();
        verify(userRepository).findByEmail("john@example.com");
        verify(userRepository).findByEmail("jane@example.com");
    }

    @Test
    void findAll_ShouldReturnMembersWithDefaultRole_WhenUserNotFound() {
        // Given
        when(memberRepository.findAll()).thenReturn(Arrays.asList(member));
        when(userRepository.findByEmail("john@example.com")).thenReturn(Optional.empty());

        // When
        List<MemberDTO> result = memberService.findAll();

        // Then
        assertEquals(1, result.size());
        MemberDTO dto = result.get(0);
        assertEquals(Role.ROLE_USER, dto.getRole());

        verify(memberRepository).findAll();
        verify(userRepository).findByEmail("john@example.com");
    }

    @Test
    void findById_ShouldReturnMemberWithRole_WhenFound() {
        // Given
        when(memberRepository.findById("member123")).thenReturn(Optional.of(member));
        when(userRepository.findByMemberId("member123")).thenReturn(Optional.of(user));

        // When
        Optional<MemberDTO> result = memberService.findById("member123");

        // Then
        assertTrue(result.isPresent());
        MemberDTO dto = result.get();
        assertEquals("member123", dto.getId());
        assertEquals("John Doe", dto.getName());
        assertEquals("john@example.com", dto.getEmail());
        assertEquals("1234567890", dto.getPhoneNumber());
        assertEquals(Role.ROLE_USER, dto.getRole());

        verify(memberRepository).findById("member123");
        verify(userRepository).findByMemberId("member123");
    }

    @Test
    void findById_ShouldReturnMemberWithDefaultRole_WhenUserNotFound() {
        // Given
        when(memberRepository.findById("member123")).thenReturn(Optional.of(member));
        when(userRepository.findByMemberId("member123")).thenReturn(Optional.empty());

        // When
        Optional<MemberDTO> result = memberService.findById("member123");

        // Then
        assertTrue(result.isPresent());
        assertEquals(Role.ROLE_USER, result.get().getRole());

        verify(memberRepository).findById("member123");
        verify(userRepository).findByMemberId("member123");
    }

    @Test
    void findById_ShouldReturnEmpty_WhenMemberNotFound() {
        // Given
        when(memberRepository.findById("nonexistent")).thenReturn(Optional.empty());

        // When
        Optional<MemberDTO> result = memberService.findById("nonexistent");

        // Then
        assertFalse(result.isPresent());
        verify(memberRepository).findById("nonexistent");
        verify(userRepository, never()).findByMemberId(anyString());
    }

    @Test
    void save_ShouldThrowValidationException_WhenEmailAlreadyExists() {
        // Given
        Member existingMember = new Member();
        existingMember.setId("existing123");
        existingMember.setEmail("john@example.com");

        Member newMember = new Member();
        newMember.setEmail("john@example.com");

        when(memberRepository.findByEmail("john@example.com")).thenReturn(Optional.of(existingMember));

        // When & Then
        ValidationException exception = assertThrows(ValidationException.class, () -> {
            memberService.save(newMember);
        });

        assertEquals("Email already exists", exception.getMessage());
        verify(memberRepository).findByEmail("john@example.com");
        verify(memberRepository, never()).save(any(Member.class));
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void update_ShouldUpdateMember_WhenValidRequest() {
        // Given
        Member updatedMember = new Member();
        updatedMember.setId("member123");
        updatedMember.setName("John Updated");
        updatedMember.setEmail("john@example.com");
        updatedMember.setPhoneNumber("9876543210");

        when(memberRepository.findById("member123")).thenReturn(Optional.of(member));
        when(memberRepository.save(updatedMember)).thenReturn(updatedMember);

        // When
        Member result = memberService.update(updatedMember);

        // Then
        assertEquals(updatedMember, result);
        verify(memberRepository).findById("member123");
        verify(memberRepository).save(updatedMember);
    }

    @Test
    void update_ShouldThrowValidationException_WhenMemberIdIsNull() {
        // Given
        Member memberWithoutId = new Member();
        memberWithoutId.setId(null);

        // When & Then
        ValidationException exception = assertThrows(ValidationException.class, () -> {
            memberService.update(memberWithoutId);
        });

        assertEquals("Member ID cannot be null", exception.getMessage());
        verify(memberRepository, never()).findById(anyString());
        verify(memberRepository, never()).save(any(Member.class));
    }

    @Test
    void update_ShouldThrowMemberNotFoundException_WhenMemberNotFound() {
        // Given
        Member updatedMember = new Member();
        updatedMember.setId("nonexistent");

        when(memberRepository.findById("nonexistent")).thenReturn(Optional.empty());

        // When & Then
        MemberService.MemberNotFoundException exception = assertThrows(MemberService.MemberNotFoundException.class, () -> {
            memberService.update(updatedMember);
        });

        assertEquals("Member not found", exception.getMessage());
        verify(memberRepository).findById("nonexistent");
        verify(memberRepository, never()).save(any(Member.class));
    }

    @Test
    void updateRole_ShouldUpdateUserRole_WhenValidRequest() {
        // Given
        when(memberRepository.findById("member123")).thenReturn(Optional.of(member));
        when(userRepository.findByMemberId("member123")).thenReturn(Optional.of(user));

        // When
        MemberDTO result = memberService.updateRole("member123", Role.ROLE_ADMIN);

        // Then
        assertNotNull(result);
        assertEquals("member123", result.getId());
        assertEquals("John Doe", result.getName());
        assertEquals("john@example.com", result.getEmail());
        assertEquals("1234567890", result.getPhoneNumber());
        assertEquals(Role.ROLE_ADMIN, result.getRole());

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        assertEquals(Role.ROLE_ADMIN, userCaptor.getValue().getRole());
    }

    @Test
    void updateRole_ShouldThrowMemberNotFoundException_WhenMemberNotFound() {
        // Given
        when(memberRepository.findById("nonexistent")).thenReturn(Optional.empty());

        // When & Then
        MemberService.MemberNotFoundException exception = assertThrows(MemberService.MemberNotFoundException.class, () -> {
            memberService.updateRole("nonexistent", Role.ROLE_ADMIN);
        });

        assertEquals("Member not found", exception.getMessage());
        verify(memberRepository).findById("nonexistent");
        verify(userRepository, never()).findByMemberId(anyString());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void updateRole_ShouldThrowValidationException_WhenUserNotFound() {
        // Given
        when(memberRepository.findById("member123")).thenReturn(Optional.of(member));
        when(userRepository.findByMemberId("member123")).thenReturn(Optional.empty());

        // When & Then
        ValidationException exception = assertThrows(ValidationException.class, () -> {
            memberService.updateRole("member123", Role.ROLE_ADMIN);
        });

        assertEquals("User account not found", exception.getMessage());
        verify(memberRepository).findById("member123");
        verify(userRepository).findByMemberId("member123");
        verify(userRepository, never()).save(any(User.class));
    }

}