package com.example.taskmanagersecurity;

import com.example.taskmanagersecurity.controller.AuthController;
import com.example.taskmanagersecurity.model.User;
import com.example.taskmanagersecurity.service.JwtService;
import com.example.taskmanagersecurity.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.Set;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class AuthControllerTest {

    private MockMvc mockMvc;

    @Mock
    private UserService userService;

    @Mock
    private JwtService jwtService;

    @Mock
    private AuthenticationManager authenticationManager;

    @InjectMocks
    private AuthController authController;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        mockMvc = MockMvcBuilders.standaloneSetup(authController).build();
    }

    @Test
    void testLogin_ValidCredentials_ReturnsTokenAndUser() throws Exception {

        Authentication auth = mock(Authentication.class);
        UserDetails userDetails = org.springframework.security.core.userdetails.User
                .withUsername("razvan")
                .password("pass")
                .authorities("ROLE_USER")
                .build();

        when(auth.getPrincipal()).thenReturn(userDetails);
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(auth);
        when(jwtService.generateToken(userDetails)).thenReturn("mocktoken");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\": \"razvan\", \"password\": \"1234\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("mocktoken"))
                .andExpect(jsonPath("$.username").value("razvan"))
                .andExpect(jsonPath("$.roles").isArray());

        verify(authenticationManager, times(1)).authenticate(any());
        verify(jwtService, times(1)).generateToken(userDetails);
    }

    @Test
    void testLogin_InvalidCredentials_Returns401() throws Exception {

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Invalid credentials"));

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\": \"wrong\", \"password\": \"wrong\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Invalid credentials"));

        verify(jwtService, never()).generateToken(any());
    }

    @Test
    void testLogin_EmptyCredentials_Returns401() throws Exception {

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Invalid credentials"));

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\": \"\", \"password\": \"\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testRegister_ValidUser_ReturnsSuccess() throws Exception {

        User user = User.builder()
                .id(1L)
                .username("newuser")
                .password("encodedPassword")
                .roles(Set.of("ROLE_USER"))
                .build();

        when(userService.registerUser("newuser", "1234", Set.of("ROLE_USER")))
                .thenReturn(user);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\": \"newuser\", \"password\": \"1234\", \"role\":\"ROLE_USER\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("User registered successfully"))
                .andExpect(jsonPath("$.username").value("newuser"));

        verify(userService, times(1)).registerUser("newuser", "1234", Set.of("ROLE_USER"));
    }

    @Test
    void testRegister_DuplicateUsername_Returns400() throws Exception {

        when(userService.registerUser("duplicate", "1234", Set.of("ROLE_USER")))
                .thenThrow(new IllegalArgumentException("Username already exists"));

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\": \"duplicate\", \"password\": \"1234\", \"role\":\"ROLE_USER\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Username already exists"));
    }

    @Test
    void testRegister_WithManagerRole_ReturnsSuccess() throws Exception {

        User manager = User.builder()
                .id(2L)
                .username("manager")
                .password("encodedPassword")
                .roles(Set.of("ROLE_MANAGER"))
                .build();

        when(userService.registerUser("manager", "1234", Set.of("ROLE_MANAGER")))
                .thenReturn(manager);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\": \"manager\", \"password\": \"1234\", \"role\":\"ROLE_MANAGER\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("manager"));
    }

    @Test
    void testRegister_WithAdminRole_ReturnsSuccess() throws Exception {

        User admin = User.builder()
                .id(3L)
                .username("admin")
                .password("encodedPassword")
                .roles(Set.of("ROLE_ADMIN"))
                .build();

        when(userService.registerUser("admin", "1234", Set.of("ROLE_ADMIN")))
                .thenReturn(admin);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\": \"admin\", \"password\": \"1234\", \"role\":\"ROLE_ADMIN\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("admin"));
    }
}