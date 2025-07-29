package org.jboss.quickstarts.kitchensink.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.quickstarts.kitchensink.dto.AuthRequest;
import org.jboss.quickstarts.kitchensink.dto.MemberDTO;
import org.jboss.quickstarts.kitchensink.dto.RegisterRequest;
import org.jboss.quickstarts.kitchensink.model.Member;
import org.jboss.quickstarts.kitchensink.model.Role;
import org.jboss.quickstarts.kitchensink.model.User;
import org.jboss.quickstarts.kitchensink.repository.MemberRepository;
import org.jboss.quickstarts.kitchensink.repository.UserRepository;
import org.jboss.quickstarts.kitchensink.security.KeyPairService;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.MongoDBContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.Optional;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@Testcontainers
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@ActiveProfiles("test")
public class AuthControllerIntegrationTest {

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
    private UserRepository userRepository;

    @Autowired
    private MemberRepository memberRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private KeyPairService keyPairService;

    private static final String ADMIN_EMAIL = "admin@test.com";
    private static final String ADMIN_PASSWORD = "admin123";
    private static final String USER_EMAIL = "user@test.com";
    private static final String USER_PASSWORD = "user123";

    private String adminToken;
    private String userToken;

    @BeforeAll
    void setup() {
        // Clean up database
        userRepository.deleteAll();
        memberRepository.deleteAll();

        // Create admin user and member
        Member adminMember = Member.builder()
                .name("Admin User")
                .email(ADMIN_EMAIL)
                .phoneNumber("1234567890")
                .build();
        adminMember = memberRepository.save(adminMember);

        User adminUser = User.builder()
                .email(ADMIN_EMAIL)
                .password(passwordEncoder.encode(ADMIN_PASSWORD))
                .role(Role.ROLE_ADMIN)
                .memberId(adminMember.getId())
                .build();
        userRepository.save(adminUser);

        // Create regular user and member
        Member regularMember = Member.builder()
                .name("Regular User")
                .email(USER_EMAIL)
                .phoneNumber("0987654321")
                .build();
        regularMember = memberRepository.save(regularMember);

        User regularUser = User.builder()
                .email(USER_EMAIL)
                .password(passwordEncoder.encode(USER_PASSWORD))
                .role(Role.ROLE_USER)
                .memberId(regularMember.getId())
                .build();
        userRepository.save(regularUser);

        // Create additional test members
        for (int i = 1; i <= 3; i++) {
            Member testMember = Member.builder()
                    .name("Test Member " + i)
                    .email("test" + i + "@test.com")
                    .phoneNumber("555555555" + i)
                    .build();
            memberRepository.save(testMember);
        }
    }

    @AfterAll
    void cleanup() {
        memberRepository.deleteAll();
        userRepository.deleteAll();
    }

    private String getAuthToken(String email, String password) throws Exception {
        AuthRequest request = new AuthRequest(
                email,
                keyPairService.encryptPassword(password)
        );

        MvcResult result = mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andReturn();

        String response = result.getResponse().getContentAsString();
        return objectMapper.readTree(response).get("token").asText();
    }

    @Test
    @Order(1)
    @DisplayName("Should authenticate admin user with correct password")
    void authenticate_AdminWithCorrectPassword_ShouldSucceed() throws Exception {
        // Create auth request
        AuthRequest request = new AuthRequest(
                ADMIN_EMAIL,
                keyPairService.encryptPassword(ADMIN_PASSWORD)
        );

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists())
                .andExpect(jsonPath("$.token").isString());
    }

    @Test
    @Order(2)
    @DisplayName("Should fail to authenticate admin user with incorrect password")
    void authenticate_AdminWithIncorrectPassword_ShouldFail() throws Exception {
        // Create auth request with wrong password
        AuthRequest request = new AuthRequest(
                ADMIN_EMAIL,
                keyPairService.encryptPassword("wrongpassword")
        );

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(3)
    @DisplayName("Should authenticate regular user with correct password")
    void authenticate_UserWithCorrectPassword_ShouldSucceed() throws Exception {
        // Create auth request
        AuthRequest request = new AuthRequest(
                USER_EMAIL,
                keyPairService.encryptPassword(USER_PASSWORD)
        );

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists())
                .andExpect(jsonPath("$.token").isString());
    }

    @Test
    @Order(4)
    @DisplayName("Should fail to authenticate regular user with incorrect password")
    void authenticate_UserWithIncorrectPassword_ShouldFail() throws Exception {
        // Create auth request with wrong password
        AuthRequest request = new AuthRequest(
                USER_EMAIL,
                keyPairService.encryptPassword("wrongpassword")
        );

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(5)
    @DisplayName("Admin should successfully fetch all members")
    void getAllMembers_AsAdmin_ShouldSucceed() throws Exception {
        // Get admin token
        String adminToken = getAuthToken(ADMIN_EMAIL, ADMIN_PASSWORD);

        // Test fetching all members
        mockMvc.perform(get("/api/members")
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$", hasSize(5))) // 2 users + 3 test members
                .andExpect(jsonPath("$[*].email", hasItems(ADMIN_EMAIL, USER_EMAIL)))
                .andExpect(jsonPath("$[*].name", hasItems("Admin User", "Regular User")));
    }

    @Test
    @Order(6)
    @DisplayName("Regular user should fail to fetch all members")
    void getAllMembers_AsUser_ShouldFail() throws Exception {
        // Get user token
        String userToken = getAuthToken(USER_EMAIL, USER_PASSWORD);

        // Test fetching all members
        mockMvc.perform(get("/api/members")
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    @Test
    @Order(7)
    @DisplayName("Admin should successfully delete a member")
    void deleteMember_AsAdmin_ShouldSucceed() throws Exception {
        // Create a member to delete
        Member memberToDelete = Member.builder()
                .name("To Delete")
                .email("todelete@test.com")
                .phoneNumber("1231231234")
                .build();
        memberToDelete = memberRepository.save(memberToDelete);

        // Get admin token
        String adminToken = getAuthToken(ADMIN_EMAIL, ADMIN_PASSWORD);

        // Test deleting the member
        mockMvc.perform(delete("/api/members/{id}", memberToDelete.getId())
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isNoContent());

        // Verify member was deleted
        assertFalse(memberRepository.findById(memberToDelete.getId()).isPresent());
    }

    @Test
    @Order(8)
    @DisplayName("Regular user should fail to delete a member")
    void deleteMember_AsUser_ShouldFail() throws Exception {
        // Create a member that we'll try to delete
        Member memberToDelete = Member.builder()
                .name("Try Delete")
                .email("trydelete@test.com")
                .phoneNumber("9879879876")
                .build();
        memberToDelete = memberRepository.save(memberToDelete);

        // Get user token
        String userToken = getAuthToken(USER_EMAIL, USER_PASSWORD);

        // Test deleting the member - should fail
        mockMvc.perform(delete("/api/members/{id}", memberToDelete.getId())
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());

        // Verify member was not deleted
        assertTrue(memberRepository.findById(memberToDelete.getId()).isPresent());

        // Cleanup
        memberRepository.delete(memberToDelete);
    }

    @Test
    @Order(9)
    @DisplayName("Regular user should not access another member's data")
    void getMember_AsUser_ShouldNotAccessOtherMemberData() throws Exception {
        // Create another member
        Member otherMember = Member.builder()
                .name("Other Member")
                .email("other@test.com")
                .phoneNumber("5555555555")
                .build();
        otherMember = memberRepository.save(otherMember);

        // Create user account for the other member
        User otherUser = User.builder()
                .email("other@test.com")
                .password(passwordEncoder.encode("other123"))
                .role(Role.ROLE_USER)
                .memberId(otherMember.getId())
                .build();
        userRepository.save(otherUser);

        // Get regular user token
        String userToken = getAuthToken(USER_EMAIL, USER_PASSWORD);

        // Try to access other member's data - should fail
        mockMvc.perform(get("/api/members/{id}", otherMember.getId())
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());

        // Verify user can access their own data
        mockMvc.perform(get("/api/members/{id}", memberRepository.findByEmail(USER_EMAIL).get().getId())
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(USER_EMAIL))
                .andExpect(jsonPath("$.name").value("Regular User"));

        // Cleanup
        userRepository.delete(otherUser);
        memberRepository.delete(otherMember);
    }

    @Test
    @Order(10)
    @DisplayName("Admin should successfully create a new member")
    void createMember_AsAdmin_ShouldSucceed() throws Exception {
        // Get admin token
        String adminToken = getAuthToken(ADMIN_EMAIL, ADMIN_PASSWORD);

        // Create new member data
        RegisterRequest newMember = new RegisterRequest(
            "newtest@test.com",
            keyPairService.encryptPassword("newtest123"),
            "New Test Member",
            "4444444444"
        );

        // Test creating new member
        MvcResult result = mockMvc.perform(post("/api/members")
                .header("Authorization", "Bearer " + adminToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(newMember)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").exists())
                .andExpect(jsonPath("$.email").value("newtest@test.com"))
                .andExpect(jsonPath("$.name").value("New Test Member"))
                .andExpect(jsonPath("$.role").value("ROLE_USER"))
                .andReturn();

        // Extract the created member's ID and verify it exists in the database
        String response = result.getResponse().getContentAsString();
        String createdMemberId = objectMapper.readTree(response).get("id").asText();
        assertTrue(memberRepository.findById(createdMemberId).isPresent());

        // Verify associated user account was created with correct role
        Optional<User> createdUser = userRepository.findByEmail("newtest@test.com");
        assertTrue(createdUser.isPresent());
        assertEquals(Role.ROLE_USER, createdUser.get().getRole());

        // Verify user can log in with the created password
        AuthRequest loginRequest = new AuthRequest(
            "newtest@test.com",
            keyPairService.encryptPassword("newtest123")
        );
        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists());

        // Cleanup
        memberRepository.deleteById(createdMemberId);
        userRepository.findByEmail("newtest@test.com").ifPresent(user -> userRepository.delete(user));
    }

    @Test
    @Order(11)
    @DisplayName("Regular user should fail to create a new member")
    void createMember_AsUser_ShouldFail() throws Exception {
        // Get user token
        String userToken = getAuthToken(USER_EMAIL, USER_PASSWORD);

        // Create new member data
        RegisterRequest newMember = new RegisterRequest(
            "unauthorized@test.com",
            keyPairService.encryptPassword("unauthorized123"),
            "Unauthorized Member",
            "6666666666"
        );

        // Test creating new member - should fail
        mockMvc.perform(post("/api/members")
                .header("Authorization", "Bearer " + userToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(newMember)))
                .andExpect(status().isForbidden());

        // Verify member was not created
        assertFalse(memberRepository.findByEmail("unauthorized@test.com").isPresent());
        assertFalse(userRepository.findByEmail("unauthorized@test.com").isPresent());
    }

    @Test
    @Order(12)
    @DisplayName("Should fail to authenticate with invalid email format")
    void authenticate_WithInvalidEmail_ShouldFail() throws Exception {
        // Create auth request with invalid email
        AuthRequest request = new AuthRequest(
                "not-an-email",  // invalid email format
                keyPairService.encryptPassword("password123")
        );

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());

        // Test with empty email
        request = new AuthRequest(
                "",  // empty email
                keyPairService.encryptPassword("password123")
        );

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());

        // Test with null email
        request = new AuthRequest(
                null,  // null email
                keyPairService.encryptPassword("password123")
        );

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }
} 