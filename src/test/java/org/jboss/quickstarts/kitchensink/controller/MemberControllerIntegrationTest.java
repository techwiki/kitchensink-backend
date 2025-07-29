package org.jboss.quickstarts.kitchensink.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.quickstarts.kitchensink.dto.MemberDTO;
import org.jboss.quickstarts.kitchensink.dto.RegisterRequest;
import org.jboss.quickstarts.kitchensink.dto.RoleUpdateRequest;
import org.jboss.quickstarts.kitchensink.model.Member;
import org.jboss.quickstarts.kitchensink.model.Role;
import org.jboss.quickstarts.kitchensink.model.User;
import org.jboss.quickstarts.kitchensink.repository.MemberRepository;
import org.jboss.quickstarts.kitchensink.repository.UserRepository;
import org.jboss.quickstarts.kitchensink.security.JwtService;
import org.jboss.quickstarts.kitchensink.security.KeyPairService;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.MongoDBContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MvcResult;
import org.jboss.quickstarts.kitchensink.dto.AuthRequest;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.hamcrest.Matchers.startsWith;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@Testcontainers
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@ActiveProfiles("test")
public class MemberControllerIntegrationTest {

    static {
        MongoDBContainer mongoDBContainer = new MongoDBContainer("mongo:6.0.8")
                .withExposedPorts(27017)
                .withReuse(true);
        mongoDBContainer.start();
        System.setProperty("MONGODB_URI", mongoDBContainer.getReplicaSetUrl());
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private MemberRepository memberRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private KeyPairService keyPairService;

    private String adminToken;
    private String userToken;
    private Member testMember;
    private User testUser;
    private User adminUser;

    @BeforeAll
    void setup() {
        // Clean up databases
        memberRepository.deleteAll();
        userRepository.deleteAll();

        // Create admin user
        adminUser = User.builder()
                .email("admin@test.com")
                .password(passwordEncoder.encode("admin123"))
                .role(Role.ROLE_ADMIN)
                .build();
        adminUser = userRepository.save(adminUser);
        adminToken = jwtService.generateToken(adminUser);

        // Create test member and associated user
        testMember = new Member();
        testMember.setName("Test User");
        testMember.setEmail("user@test.com");
        testMember.setPhoneNumber("1234567890");
        testMember = memberRepository.save(testMember);

        testUser = User.builder()
                .email("user@test.com")
                .password(passwordEncoder.encode("user123"))
                .role(Role.ROLE_USER)
                .memberId(testMember.getId())
                .build();
        testUser = userRepository.save(testUser);
        userToken = jwtService.generateToken(testUser);
    }

    @AfterAll
    void cleanup() {
        memberRepository.deleteAll();
        userRepository.deleteAll();
    }

    private Member createTestMember(String email) {
        Member member = new Member();
        member.setName("Test Member");
        member.setEmail(email);
        member.setPhoneNumber("1234567890");
        return member;
    }

    private String createAuthHeader(String token) {
        return "Bearer " + token;
    }

    @Nested
    @DisplayName("Get All Members Tests")
    class GetAllMembersTests {
        
        @Test
        @Order(1)
        @DisplayName("Should return all members when authenticated as admin")
        void getAllMembers_AsAdmin_ShouldReturnAllMembers() throws Exception {
            // Create additional test members
            List<Member> additionalMembers = new ArrayList<>();
            for (int i = 1; i <= 3; i++) {
                Member member = createTestMember("test" + i + "@test.com");
                additionalMembers.add(memberRepository.save(member));
            }

            mockMvc.perform(get("/api/members")
                    .header("Authorization", createAuthHeader(adminToken)))
                    .andExpect(status().isOk())
                    .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                    .andExpect(jsonPath("$", hasSize(greaterThanOrEqualTo(4))))
                    .andExpect(jsonPath("$[0].email", notNullValue()));

            // Cleanup additional members
            memberRepository.deleteAll(additionalMembers);
        }

        @Test
        @Order(2)
        @DisplayName("Should return forbidden when authenticated as regular user")
        void getAllMembers_AsUser_ShouldReturnForbidden() throws Exception {
            mockMvc.perform(get("/api/members")
                    .header("Authorization", createAuthHeader(userToken)))
                    .andExpect(status().isForbidden());
        }

        @Test
        @Order(3)
        @DisplayName("Should return unauthorized when not authenticated")
        void getAllMembers_WithNoAuth_ShouldReturnUnauthorized() throws Exception {
            mockMvc.perform(get("/api/members"))
                    .andExpect(status().isUnauthorized());
        }
    }

    @Nested
    @DisplayName("Get Single Member Tests")
    class GetSingleMemberTests {

        @Test
        @Order(1)
        @DisplayName("Should return member when authenticated as admin")
        void getMember_AsAdmin_ShouldReturnMember() throws Exception {
            mockMvc.perform(get("/api/members/{id}", testMember.getId())
                    .header("Authorization", createAuthHeader(adminToken)))
                    .andExpect(status().isOk())
                    .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                    .andExpect(jsonPath("$.id", is(testMember.getId())))
                    .andExpect(jsonPath("$.email", is(testMember.getEmail())));
        }

        @Test
        @Order(2)
        @DisplayName("Should return member when authenticated as same user")
        void getMember_AsSameUser_ShouldReturnOwnMember() throws Exception {
            mockMvc.perform(get("/api/members/{id}", testMember.getId())
                    .header("Authorization", createAuthHeader(userToken)))
                    .andExpect(status().isOk())
                    .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                    .andExpect(jsonPath("$.id", is(testMember.getId())))
                    .andExpect(jsonPath("$.email", is(testMember.getEmail())));
        }

        @Test
        @Order(3)
        @DisplayName("Should return forbidden when authenticated as different user")
        void getMember_AsDifferentUser_ShouldReturnForbidden() throws Exception {
            // Create another member and user
            Member otherMember = memberRepository.save(createTestMember("other@test.com"));
            User otherUser = User.builder()
                    .email("other@test.com")
                    .password(passwordEncoder.encode("other123"))
                    .role(Role.ROLE_USER)
                    .memberId(otherMember.getId())
                    .build();
            userRepository.save(otherUser);
            String otherToken = jwtService.generateToken(otherUser);

            mockMvc.perform(get("/api/members/{id}", testMember.getId())
                    .header("Authorization", createAuthHeader(otherToken)))
                    .andExpect(status().isForbidden());

            // Cleanup
            memberRepository.delete(otherMember);
            userRepository.delete(otherUser);
        }

        @Test
        @Order(4)
        @DisplayName("Should return not found when member doesn't exist")
        void getMember_WithInvalidId_ShouldReturnNotFound() throws Exception {
            mockMvc.perform(get("/api/members/{id}", "invalid-id")
                    .header("Authorization", createAuthHeader(adminToken)))
                    .andExpect(status().isNotFound());
        }

        @Test
        @Order(5)
        @DisplayName("Should return unauthorized when not authenticated")
        void getMember_WithNoAuth_ShouldReturnUnauthorized() throws Exception {
            mockMvc.perform(get("/api/members/{id}", testMember.getId()))
                    .andExpect(status().isUnauthorized());
        }
    }

    @Nested
    @DisplayName("Create Member Tests")
    class CreateMemberTests {

        @Test
        @Order(1)
        @DisplayName("Should create member when authenticated as admin")
        void createMember_AsAdmin_ShouldCreateMember() throws Exception {
            RegisterRequest request = new RegisterRequest(
                "newmember@test.com",
                keyPairService.encryptPassword("newmember123"),
                "New Member",
                "9876543210"
            );
            
            MvcResult result = mockMvc.perform(post("/api/members")
                    .header("Authorization", createAuthHeader(adminToken))
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.id").exists())
                    .andExpect(jsonPath("$.email").value("newmember@test.com"))
                    .andExpect(jsonPath("$.name").value("New Member"))
                    .andExpect(jsonPath("$.phoneNumber").value("9876543210"))
                    .andExpect(jsonPath("$.role").value("ROLE_USER"))
                    .andReturn();

            // Extract the created member's ID
            String response = result.getResponse().getContentAsString();
            String createdMemberId = objectMapper.readTree(response).get("id").asText();

            // Verify member was created in database
            Optional<Member> createdMember = memberRepository.findById(createdMemberId);
            assertTrue(createdMember.isPresent());
            assertEquals("newmember@test.com", createdMember.get().getEmail());

            // Verify user was created with correct role
            Optional<User> createdUser = userRepository.findByEmail("newmember@test.com");
            assertTrue(createdUser.isPresent());
            assertEquals(Role.ROLE_USER, createdUser.get().getRole());
            assertEquals(createdMemberId, createdUser.get().getMemberId());

            // Verify can login with created credentials
            AuthRequest loginRequest = new AuthRequest(
                "newmember@test.com",
                keyPairService.encryptPassword("newmember123")
            );

            mockMvc.perform(post("/api/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(loginRequest)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.token").exists());

            // Cleanup
            memberRepository.deleteById(createdMemberId);
            userRepository.delete(createdUser.get());
        }

        @Test
        @Order(2)
        @DisplayName("Should return forbidden when authenticated as regular user")
        void createMember_AsUser_ShouldReturnForbidden() throws Exception {
            RegisterRequest request = new RegisterRequest(
                "forbidden@test.com",
                keyPairService.encryptPassword("forbidden123"),
                "Forbidden User",
                "9876543210"
            );
            
            mockMvc.perform(post("/api/members")
                    .header("Authorization", createAuthHeader(userToken))
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isForbidden());
        }

        @Test
        @Order(3)
        @DisplayName("Should return bad request when data is invalid")
        void createMember_WithInvalidData_ShouldReturnBadRequest() throws Exception {
            // Test with missing name
            RegisterRequest missingName = new RegisterRequest(
                "test@test.com",
                keyPairService.encryptPassword("test123"),
                "Test 123",  // name with number
                "1234567890"
            );
            
            mockMvc.perform(post("/api/members")
                    .header("Authorization", createAuthHeader(adminToken))
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(missingName)))
                    .andExpect(status().isBadRequest());

            // Test with invalid email
            RegisterRequest invalidEmail = new RegisterRequest(
                "not-an-email",
                keyPairService.encryptPassword("test123"),
                "Test Name",
                "1234567890"
            );
            
            mockMvc.perform(post("/api/members")
                    .header("Authorization", createAuthHeader(adminToken))
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(invalidEmail)))
                    .andExpect(status().isBadRequest());

            // Test with invalid phone number (too short)
            RegisterRequest invalidPhone = new RegisterRequest(
                "test@test.com",
                keyPairService.encryptPassword("test123"),
                "Test Name",
                "123"  // too short
            );
            
            mockMvc.perform(post("/api/members")
                    .header("Authorization", createAuthHeader(adminToken))
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(invalidPhone)))
                    .andExpect(status().isBadRequest());

            // Test with missing password
            RegisterRequest missingPassword = new RegisterRequest(
                "test@test.com",
                "",  // empty password
                "Test Name",
                "1234567890"
            );
            
            mockMvc.perform(post("/api/members")
                    .header("Authorization", createAuthHeader(adminToken))
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(missingPassword)))
                    .andExpect(status().isBadRequest());

            // Test with null values
            RegisterRequest nullValues = new RegisterRequest(
                null,
                null,
                null,
                null
            );
            
            mockMvc.perform(post("/api/members")
                    .header("Authorization", createAuthHeader(adminToken))
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(nullValues)))
                    .andExpect(status().isBadRequest());
        }

        @Test
        @Order(4)
        @DisplayName("Should return conflict when email already exists")
        void createMember_WithDuplicateEmail_ShouldReturnConflict() throws Exception {
            RegisterRequest duplicateRequest = new RegisterRequest(
                testMember.getEmail(),  // using existing email
                keyPairService.encryptPassword("duplicate123"),
                "Duplicate User",
                "9998887777"
            );
            
            mockMvc.perform(post("/api/members")
                    .header("Authorization", createAuthHeader(adminToken))
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(duplicateRequest)))
                    .andExpect(status().isConflict());
        }
    }

    @Nested
    @DisplayName("Update Member Tests")
    class UpdateMemberTests {

        @Test
        @Order(1)
        @DisplayName("Should update member when authenticated as admin")
        void updateMember_AsAdmin_ShouldUpdateMember() throws Exception {
            Member memberToUpdate = createTestMember("toupdate@test.com");
            memberToUpdate = memberRepository.save(memberToUpdate);

            memberToUpdate.setName("Updated Name");
            memberToUpdate.setPhoneNumber("9876543210");

            mockMvc.perform(put("/api/members/{id}", memberToUpdate.getId())
                    .header("Authorization", createAuthHeader(adminToken))
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(memberToUpdate)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.name", is("Updated Name")))
                    .andExpect(jsonPath("$.phoneNumber", is("9876543210")));

            // Cleanup
            memberRepository.deleteById(memberToUpdate.getId());
        }

        @Test
        @Order(2)
        @DisplayName("Should update own member when authenticated as same user")
        void updateMember_AsSameUser_ShouldUpdateOwnMember() throws Exception {
            testMember.setName("Updated Own Name");
            
            mockMvc.perform(put("/api/members/{id}", testMember.getId())
                    .header("Authorization", createAuthHeader(userToken))
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(testMember)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.name", is("Updated Own Name")));
        }

        @Test
        @Order(3)
        @DisplayName("Should return forbidden when updating other user's member")
        void updateMember_AsDifferentUser_ShouldReturnForbidden() throws Exception {
            // Create another member and user
            Member otherMember = memberRepository.save(createTestMember("other2@test.com"));
            User otherUser = User.builder()
                    .email("other2@test.com")
                    .password(passwordEncoder.encode("other123"))
                    .role(Role.ROLE_USER)
                    .memberId(otherMember.getId())
                    .build();
            userRepository.save(otherUser);
            String otherToken = jwtService.generateToken(otherUser);

            testMember.setName("Unauthorized Update");
            
            mockMvc.perform(put("/api/members/{id}", testMember.getId())
                    .header("Authorization", createAuthHeader(otherToken))
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(testMember)))
                    .andExpect(status().isForbidden());

            // Cleanup
            memberRepository.delete(otherMember);
            userRepository.delete(otherUser);
        }

        @Test
        @Order(4)
        @DisplayName("Should return not found when member doesn't exist")
        void updateMember_WithNonexistentId_ShouldReturnNotFound() throws Exception {
            Member nonexistentMember = createTestMember("nonexistent@test.com");
            nonexistentMember.setId("nonexistent-id");
            
            mockMvc.perform(put("/api/members/{id}", "nonexistent-id")
                    .header("Authorization", createAuthHeader(adminToken))
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(nonexistentMember)))
                    .andExpect(status().isNotFound());
        }

        @Test
        @Order(5)
        @DisplayName("Should return bad request when data is invalid")
        void updateMember_WithInvalidData_ShouldReturnBadRequest() throws Exception {
            Member invalidMember = new Member();
            invalidMember.setId(testMember.getId());
            // Missing required fields
            
            mockMvc.perform(put("/api/members/{id}", testMember.getId())
                    .header("Authorization", createAuthHeader(adminToken))
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(invalidMember)))
                    .andExpect(status().isBadRequest());
        }
    }

    @Nested
    @DisplayName("Delete Member Tests")
    class DeleteMemberTests {

        @Test
        @Order(1)
        @DisplayName("Should delete member when authenticated as admin")
        void deleteMember_AsAdmin_ShouldDeleteMember() throws Exception {
            Member memberToDelete = createTestMember("todelete@test.com");
            memberToDelete = memberRepository.save(memberToDelete);

            mockMvc.perform(delete("/api/members/{id}", memberToDelete.getId())
                    .header("Authorization", createAuthHeader(adminToken)))
                    .andExpect(status().isNoContent());

            // Verify deletion
            assertFalse(memberRepository.findById(memberToDelete.getId()).isPresent());
        }

        @Test
        @Order(2)
        @DisplayName("Should return forbidden when authenticated as regular user")
        void deleteMember_AsUser_ShouldReturnForbidden() throws Exception {
            mockMvc.perform(delete("/api/members/{id}", testMember.getId())
                    .header("Authorization", createAuthHeader(userToken)))
                    .andExpect(status().isForbidden());
        }

        @Test
        @Order(3)
        @DisplayName("Should return not found when member doesn't exist")
        void deleteMember_WithNonexistentId_ShouldReturnNotFound() throws Exception {
            mockMvc.perform(delete("/api/members/{id}", "nonexistent-id")
                    .header("Authorization", createAuthHeader(adminToken)))
                    .andExpect(status().isNotFound());
        }

        @Test
        @Order(4)
        @DisplayName("Should delete both member and associated user")
        void deleteMember_WithAssociatedUser_ShouldDeleteBoth() throws Exception {
            // Create new member and associated user
            Member memberToDelete = createTestMember("deletewithusr@test.com");
            memberToDelete = memberRepository.save(memberToDelete);
            
            User userToDelete = User.builder()
                    .email("deletewithusr@test.com")
                    .password(passwordEncoder.encode("password"))
                    .role(Role.ROLE_USER)
                    .memberId(memberToDelete.getId())
                    .build();
            userToDelete = userRepository.save(userToDelete);

            mockMvc.perform(delete("/api/members/{id}", memberToDelete.getId())
                    .header("Authorization", createAuthHeader(adminToken)))
                    .andExpect(status().isNoContent());

            // Verify both member and user are deleted
            assertFalse(memberRepository.findById(memberToDelete.getId()).isPresent());
            assertFalse(userRepository.findById(userToDelete.getId()).isPresent());
        }
    }

    @Nested
    @DisplayName("Member Role Management Tests")
    class MemberRoleTests {

        @Test
        @Order(1)
        @DisplayName("Should return forbidden when authenticated as regular user")
        void updateMemberRole_AsUser_ShouldReturnForbidden() throws Exception {
            // Create a separate member for this test
            Member testMemberForRole = memberRepository.save(createTestMember("roletest@test.com"));
            RoleUpdateRequest request = new RoleUpdateRequest(Role.ROLE_ADMIN);

            mockMvc.perform(patch("/api/members/{id}/role", testMemberForRole.getId())
                    .header("Authorization", createAuthHeader(userToken))
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isForbidden());

            // Cleanup
            memberRepository.delete(testMemberForRole);
        }

        @Test
        @Order(2)
        @DisplayName("Should update member role when authenticated as admin")
        void updateMemberRole_AsAdmin_ShouldUpdateRole() throws Exception {
            // Create a separate member for this test
            Member testMemberForRole = memberRepository.save(createTestMember("roleadmin@test.com"));
            User testUserForRole = User.builder()
                    .email("roleadmin@test.com")
                    .password(passwordEncoder.encode("password"))
                    .role(Role.ROLE_USER)
                    .memberId(testMemberForRole.getId())
                    .build();
            testUserForRole = userRepository.save(testUserForRole);

            RoleUpdateRequest request = new RoleUpdateRequest(Role.ROLE_ADMIN);

            mockMvc.perform(patch("/api/members/{id}/role", testMemberForRole.getId())
                    .header("Authorization", createAuthHeader(adminToken))
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.role", is(Role.ROLE_ADMIN.name())));

            // Verify user role is updated
            User updatedUser = userRepository.findByEmail(testMemberForRole.getEmail()).orElseThrow();
            assertEquals(Role.ROLE_ADMIN, updatedUser.getRole());

            // Cleanup
            userRepository.delete(testUserForRole);
            memberRepository.delete(testMemberForRole);
        }

        @Test
        @Order(3)
        @DisplayName("Should return bad request when role is invalid")
        void updateMemberRole_WithInvalidRole_ShouldReturnBadRequest() throws Exception {
            String invalidRequest = "{\"role\": \"INVALID_ROLE\"}";

            mockMvc.perform(patch("/api/members/{id}/role", testMember.getId())
                    .header("Authorization", createAuthHeader(adminToken))
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(invalidRequest))
                    .andExpect(status().isBadRequest());
        }

        @Test
        @Order(4)
        @DisplayName("Should return not found when member doesn't exist")
        void updateMemberRole_WithNonexistentId_ShouldReturnNotFound() throws Exception {
            RoleUpdateRequest request = new RoleUpdateRequest(Role.ROLE_ADMIN);

            mockMvc.perform(patch("/api/members/nonexistent-id/role")
                    .header("Authorization", createAuthHeader(adminToken))
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isNotFound());
        }
    }

    @Nested
    @DisplayName("Get Current Member Tests")
    class GetCurrentMemberTests {

        @Test
        @Order(1)
        @DisplayName("Should return current member profile")
        void getCurrentMember_WithValidUser_ShouldReturnMember() throws Exception {
            mockMvc.perform(get("/api/members/me")
                    .header("Authorization", createAuthHeader(userToken)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id", is(testMember.getId())))
                    .andExpect(jsonPath("$.email", is(testMember.getEmail())));
        }

        @Test
        @Order(2)
        @DisplayName("Should return not found when user has no member profile")
        void getCurrentMember_WithNoMemberId_ShouldReturnNotFound() throws Exception {
            // Create user without member profile
            User userWithoutMember = User.builder()
                    .email("nomember@test.com")
                    .password(passwordEncoder.encode("password"))
                    .role(Role.ROLE_USER)
                    .build();
            userWithoutMember = userRepository.save(userWithoutMember);
            String tokenWithoutMember = jwtService.generateToken(userWithoutMember);

            mockMvc.perform(get("/api/members/me")
                    .header("Authorization", createAuthHeader(tokenWithoutMember)))
                    .andExpect(status().isNotFound());

            // Cleanup
            userRepository.delete(userWithoutMember);
        }

        @Test
        @Order(3)
        @DisplayName("Should return unauthorized when not authenticated")
        void getCurrentMember_WithNoAuth_ShouldReturnUnauthorized() throws Exception {
            mockMvc.perform(get("/api/members/me"))
                    .andExpect(status().isUnauthorized());
        }
    }

    @Nested
    @DisplayName("Member Lifecycle Tests")
    class MemberLifecycleTests {

        @Test
        @Order(1)
        @DisplayName("Should handle complete member lifecycle")
        void memberLifecycle_ShouldHandleCreateUpdateDeleteFlow() throws Exception {
            // 1. Create Member
            RegisterRequest registerRequest = new RegisterRequest(
                "lifecycle@test.com",
                keyPairService.encryptPassword("lifecycle123"),
                "Lifecycle Test",
                "1234567890"
            );

            String memberId = mockMvc.perform(post("/api/members")
                    .header("Authorization", createAuthHeader(adminToken))
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(registerRequest)))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.id", notNullValue()))
                    .andExpect(jsonPath("$.email", is("lifecycle@test.com")))
                    .andExpect(jsonPath("$.name", is("Lifecycle Test")))
                    .andExpect(jsonPath("$.role", is("ROLE_USER")))
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            memberId = objectMapper.readTree(memberId).get("id").asText();

            // 2. Verify Created Member and User
            mockMvc.perform(get("/api/members/{id}", memberId)
                    .header("Authorization", createAuthHeader(adminToken)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.email", is("lifecycle@test.com")));

            // Verify user was created
            assertTrue(userRepository.findByEmail("lifecycle@test.com").isPresent());
            assertEquals(Role.ROLE_USER, userRepository.findByEmail("lifecycle@test.com").get().getRole());

            // 3. Update Member
            Member memberToUpdate = memberRepository.findById(memberId).get();
            memberToUpdate.setName("Updated Lifecycle Name");
            memberToUpdate.setPhoneNumber("9876543210");

            mockMvc.perform(put("/api/members/{id}", memberId)
                    .header("Authorization", createAuthHeader(adminToken))
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(MemberDTO.fromMember(memberToUpdate, Role.ROLE_USER))))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.name", is("Updated Lifecycle Name")))
                    .andExpect(jsonPath("$.phoneNumber", is("9876543210")));

            // 4. Update Role
            RoleUpdateRequest roleRequest = new RoleUpdateRequest(Role.ROLE_ADMIN);
            mockMvc.perform(patch("/api/members/{id}/role", memberId)
                    .header("Authorization", createAuthHeader(adminToken))
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(roleRequest)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.role", is(Role.ROLE_ADMIN.name())));

            // 5. Delete Member
            mockMvc.perform(delete("/api/members/{id}", memberId)
                    .header("Authorization", createAuthHeader(adminToken)))
                    .andExpect(status().isNoContent());

            // 6. Verify Deletion of both Member and User
            mockMvc.perform(get("/api/members/{id}", memberId)
                    .header("Authorization", createAuthHeader(adminToken)))
                    .andExpect(status().isNotFound());
            assertFalse(userRepository.findByEmail("lifecycle@test.com").isPresent());
        }
    }

}