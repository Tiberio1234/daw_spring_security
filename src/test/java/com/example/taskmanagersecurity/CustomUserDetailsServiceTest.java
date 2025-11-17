package com.example.taskmanagersecurity;

import com.example.taskmanagersecurity.model.User;
import com.example.taskmanagersecurity.repository.UserRepository;
import com.example.taskmanagersecurity.service.CustomUserDetailsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class CustomUserDetailsServiceTest {

    @Mock
    private UserRepository userRepository;

    private CustomUserDetailsService service;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        service = new CustomUserDetailsService(userRepository);
    }

    @Test
    void testLoadUserByUsername_UserExists_ReturnsUserDetails() {

        User user = User.builder()
                .id(1L)
                .username("razvan")
                .password("encodedPassword")
                .roles(Set.of("ROLE_USER"))
                .build();

        when(userRepository.findByUsername("razvan")).thenReturn(Optional.of(user));

        UserDetails userDetails = service.loadUserByUsername("razvan");

        assertNotNull(userDetails);
        assertEquals("razvan", userDetails.getUsername());
        assertEquals("encodedPassword", userDetails.getPassword());
        assertTrue(userDetails.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_USER")));
        assertTrue(userDetails.isEnabled());
        assertTrue(userDetails.isAccountNonExpired());
        assertTrue(userDetails.isAccountNonLocked());
        assertTrue(userDetails.isCredentialsNonExpired());

        verify(userRepository, times(1)).findByUsername("razvan");
    }

    @Test
    void testLoadUserByUsername_UserNotFound_ThrowsException() {

        when(userRepository.findByUsername("missing")).thenReturn(Optional.empty());

        UsernameNotFoundException exception = assertThrows(
                UsernameNotFoundException.class,
                () -> service.loadUserByUsername("missing")
        );

        assertNotNull(exception);
        assertNotNull(exception.getMessage());
        verify(userRepository, times(1)).findByUsername("missing");
    }

    @Test
    void testLoadUserByUsername_WithMultipleRoles_ReturnsAllAuthorities() {

        User user = User.builder()
                .id(2L)
                .username("admin")
                .password("encodedPassword")
                .roles(Set.of("ROLE_USER", "ROLE_ADMIN", "ROLE_MANAGER"))
                .build();

        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(user));

        UserDetails userDetails = service.loadUserByUsername("admin");

        assertEquals(3, userDetails.getAuthorities().size());
        assertTrue(userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .allMatch(role -> role.equals("ROLE_USER") ||
                        role.equals("ROLE_ADMIN") ||
                        role.equals("ROLE_MANAGER")));
    }

    @Test
    void testLoadUserByUsername_WithManagerRole_ReturnsCorrectAuthority() {

        User manager = User.builder()
                .id(3L)
                .username("manager")
                .password("encodedPassword")
                .roles(Set.of("ROLE_MANAGER"))
                .build();

        when(userRepository.findByUsername("manager")).thenReturn(Optional.of(manager));

        UserDetails userDetails = service.loadUserByUsername("manager");

        assertEquals(1, userDetails.getAuthorities().size());
        assertTrue(userDetails.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_MANAGER")));
    }

    @Test
    void testLoadUserByUsername_CaseSensitive() {

        User user = User.builder()
                .id(4L)
                .username("TestUser")
                .password("encodedPassword")
                .roles(Set.of("ROLE_USER"))
                .build();

        when(userRepository.findByUsername("TestUser")).thenReturn(Optional.of(user));
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.empty());

        UserDetails userDetails = service.loadUserByUsername("TestUser");
        assertNotNull(userDetails);
        assertEquals("TestUser", userDetails.getUsername());

        assertThrows(UsernameNotFoundException.class,
                () -> service.loadUserByUsername("testuser"));
    }

    @Test
    void testLoadUserByUsername_NullUsername_ThrowsException() {

        assertThrows(UsernameNotFoundException.class,
                () -> service.loadUserByUsername(null));
    }

    @Test
    void testLoadUserByUsername_EmptyUsername_ThrowsException() {

        when(userRepository.findByUsername("")).thenReturn(Optional.empty());

        assertThrows(UsernameNotFoundException.class,
                () -> service.loadUserByUsername(""));
    }
}