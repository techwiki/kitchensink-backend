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
    void save_ShouldCreateMemberAndUser_WhenEmailNotExists() {
        // Given
        Member newMember = new Member();
        newMember.setName("John Doe");
        newMember.setEmail("john@example.com");
        newMember.setPhoneNumber("1234567890");

        when(memberRepository.findByEmail("john@example.com")).thenReturn(Optional.empty());
        when(memberRepository.save(newMember)).thenReturn(member);
        when(userRepository.findByEmail("john@example.com")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("changeme123")).thenReturn("hashedDefaultPassword");

        // When
        Member result = memberService.save(newMember);

        // Then
        assertEquals(member, result);

        // Verify member was saved
        verify(memberRepository).findByEmail("john@example.com");
        verify(memberRepository).save(newMember);

        // Verify user was created with default password
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        User savedUser = userCaptor.getValue();
        assertEquals("john@example.com", savedUser.getEmail());
        assertEquals("hashedDefaultPassword", savedUser.getPassword());
        assertEquals(Role.ROLE_USER, savedUser.getRole());
        assertEquals("member123", savedUser.getMemberId());
    }

    @Test
    void save_ShouldUpdateExistingUserMemberId_WhenUserAlreadyExists() {
        // Given
        Member newMember = new Member();
        newMember.setName("John Doe");
        newMember.setEmail("john@example.com");
        newMember.setPhoneNumber("1234567890");

        User existingUser = User.builder()
                .id("existingUser")
                .email("john@example.com")
                .password("existingPassword")
                .role(Role.ROLE_ADMIN)
                .memberId("oldMemberId")
                .build();

        when(memberRepository.findByEmail("john@example.com")).thenReturn(Optional.empty());
        when(memberRepository.save(newMember)).thenReturn(member);
        when(userRepository.findByEmail("john@example.com")).thenReturn(Optional.of(existingUser));

        // When
        Member result = memberService.save(newMember);

        // Then
        assertEquals(member, result);

        // Verify existing user's memberId was updated
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        User updatedUser = userCaptor.getValue();
        assertEquals("member123", updatedUser.getMemberId());
        assertEquals("existingPassword", updatedUser.getPassword()); // Password should remain unchanged
        assertEquals(Role.ROLE_ADMIN, updatedUser.getRole()); // Role should remain unchanged
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
    void update_ShouldThrowValidationException_WhenMemberNotFound() {
        // Given
        Member updatedMember = new Member();
        updatedMember.setId("nonexistent");

        when(memberRepository.findById("nonexistent")).thenReturn(Optional.empty());

        // When & Then
        ValidationException exception = assertThrows(ValidationException.class, () -> {
            memberService.update(updatedMember);
        });

        assertEquals("Member not found", exception.getMessage());
        verify(memberRepository).findById("nonexistent");
        verify(memberRepository, never()).save(any(Member.class));
    }

    @Test
    void update_ShouldThrowValidationException_WhenEmailChangedToExistingEmail() {
        // Given
        Member existingMemberWithSameEmail = new Member();
        existingMemberWithSameEmail.setId("other123");
        existingMemberWithSameEmail.setEmail("newemail@example.com");

        Member updatedMember = new Member();
        updatedMember.setId("member123");
        updatedMember.setEmail("newemail@example.com");

        when(memberRepository.findById("member123")).thenReturn(Optional.of(member));
        when(memberRepository.findByEmail("newemail@example.com")).thenReturn(Optional.of(existingMemberWithSameEmail));

        // When & Then
        ValidationException exception = assertThrows(ValidationException.class, () -> {
            memberService.update(updatedMember);
        });

        assertEquals("Email already exists", exception.getMessage());
        verify(memberRepository).findById("member123");
        verify(memberRepository).findByEmail("newemail@example.com");
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
    void updateRole_ShouldThrowValidationException_WhenMemberNotFound() {
        // Given
        when(memberRepository.findById("nonexistent")).thenReturn(Optional.empty());

        // When & Then
        ValidationException exception = assertThrows(ValidationException.class, () -> {
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

    @Test
    void delete_ShouldDeleteMember() {
        // When
        memberService.delete("member123");

        // Then
        verify(memberRepository).deleteById("member123");
    }

    @Test
    void save_ShouldEncodeDefaultPassword() {
        // Given
        Member newMember = new Member();
        newMember.setEmail("john@example.com");

        when(memberRepository.findByEmail("john@example.com")).thenReturn(Optional.empty());
        when(memberRepository.save(newMember)).thenReturn(member);
        when(userRepository.findByEmail("john@example.com")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("changeme123")).thenReturn("hashedDefaultPassword");

        // When
        memberService.save(newMember);

        // Then
        verify(passwordEncoder).encode("changeme123");
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        assertEquals("hashedDefaultPassword", userCaptor.getValue().getPassword());
    }
} 