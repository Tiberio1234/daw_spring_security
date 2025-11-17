package com.example.taskmanagersecurity.config;

import com.example.taskmanagersecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {

    private final UserService userService;

    @Override
    public void run(String... args) throws Exception {
        try {
            // Create admin user
            userService.registerUser("admin", "admin123",
                    Set.of("ROLE_ADMIN"));

            // Create regular user
            userService.registerUser("user1", "user123",
                    Set.of("ROLE_USER"));

            // Create regular user
            userService.registerUser("manager1", "manager123",
                    Set.of("ROLE_MANAGER"));

            System.out.println("Demo users created successfully!");
        } catch (IllegalArgumentException e) {
            System.out.println("Demo users already exist");
        }
    }
}