package com.example.taskmanagersecurity;

import com.example.taskmanagersecurity.security.JwtAuthenticationFilter;
import com.example.taskmanagersecurity.service.CustomUserDetailsService;
import com.example.taskmanagersecurity.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class JwtAuthenticationFilterTest {

    @Mock
    private JwtService jwtService;

    @Mock
    private CustomUserDetailsService userDetailsService;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    @InjectMocks
    private JwtAuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        SecurityContextHolder.clearContext();
    }

    @Test
    void testValidToken_AuthenticatesUser() throws ServletException, IOException {

        String token = "validToken";
        String username = "razvan";

        UserDetails userDetails = User.withUsername(username)
                .password("pass")
                .authorities("ROLE_USER")
                .build();

        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);
        when(jwtService.extractUsername(token)).thenReturn(username);
        when(userDetailsService.loadUserByUsername(username)).thenReturn(userDetails);
        when(jwtService.isTokenValid(token, userDetails)).thenReturn(true);

        filter.doFilterInternal(request, response, filterChain);

        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals(username, SecurityContextHolder.getContext().getAuthentication().getName());

        verify(userDetailsService, times(1)).loadUserByUsername(username);
        verify(jwtService, times(1)).extractUsername(token);
        verify(jwtService, times(1)).isTokenValid(token, userDetails);
        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    void testValidTokenWithManagerRole_AuthenticatesWithCorrectAuthority() throws ServletException, IOException {

        String token = "managerToken";
        UserDetails userDetails = User.withUsername("manager")
                .password("pass")
                .authorities("ROLE_MANAGER")
                .build();

        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);
        when(jwtService.extractUsername(token)).thenReturn("manager");
        when(userDetailsService.loadUserByUsername("manager")).thenReturn(userDetails);
        when(jwtService.isTokenValid(token, userDetails)).thenReturn(true);

        filter.doFilterInternal(request, response, filterChain);

        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        assertTrue(SecurityContextHolder.getContext().getAuthentication().getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_MANAGER")));
    }

    @Test
    void testMissingAuthorizationHeader_DoesNotAuthenticate() throws ServletException, IOException {

        when(request.getHeader("Authorization")).thenReturn(null);

        filter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(userDetailsService, never()).loadUserByUsername(anyString());
        verify(jwtService, never()).extractUsername(anyString());
        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    void testInvalidAuthorizationHeaderFormat_DoesNotAuthenticate() throws ServletException, IOException {

        when(request.getHeader("Authorization")).thenReturn("InvalidFormat token123");

        filter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(userDetailsService, never()).loadUserByUsername(anyString());
        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    void testEmptyBearerToken_DoesNotAuthenticate() throws ServletException, IOException {

        when(request.getHeader("Authorization")).thenReturn("Bearer ");

        filter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    void testInvalidToken_DoesNotAuthenticate() throws ServletException, IOException {

        String token = "invalidToken";
        UserDetails userDetails = User.withUsername("razvan")
                .password("pass")
                .authorities("ROLE_USER")
                .build();

        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);
        when(jwtService.extractUsername(token)).thenReturn("razvan");
        when(userDetailsService.loadUserByUsername("razvan")).thenReturn(userDetails);
        when(jwtService.isTokenValid(token, userDetails)).thenReturn(false);

        filter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(jwtService, times(1)).isTokenValid(token, userDetails);
        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    void testExpiredToken_DoesNotAuthenticate() throws ServletException, IOException {

        String token = "expiredToken";

        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);
        when(jwtService.extractUsername(token)).thenThrow(new RuntimeException("Token expired"));

        filter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    void testAlreadyAuthenticatedUser_SkipsAuthentication() throws ServletException, IOException {

        String token = "validToken";
        UserDetails existingUser = User.withUsername("existing")
                .password("pass")
                .authorities("ROLE_USER")
                .build();

        SecurityContextHolder.getContext().setAuthentication(
                new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                        existingUser, null, existingUser.getAuthorities()
                )
        );

        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);
        when(jwtService.extractUsername(token)).thenReturn("razvan");

        filter.doFilterInternal(request, response, filterChain);

        assertEquals("existing", SecurityContextHolder.getContext().getAuthentication().getName());
        verify(userDetailsService, never()).loadUserByUsername(anyString());
        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    void testMalformedToken_ContinuesFilterChain() throws ServletException, IOException {

        when(request.getHeader("Authorization")).thenReturn("Bearer malformed.token");
        when(jwtService.extractUsername(anyString())).thenThrow(new RuntimeException("Malformed JWT"));

        filter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    void testUserNotFound_ContinuesFilterChain() throws ServletException, IOException {

        String token = "validToken";

        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);
        when(jwtService.extractUsername(token)).thenReturn("nonexistent");
        when(userDetailsService.loadUserByUsername("nonexistent"))
                .thenThrow(new org.springframework.security.core.userdetails.UsernameNotFoundException("User not found"));

        filter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(filterChain, times(1)).doFilter(request, response);
    }
}