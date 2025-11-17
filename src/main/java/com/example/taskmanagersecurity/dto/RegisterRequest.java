package com.example.taskmanagersecurity.dto;

import lombok.Data;

import java.util.Set;

@Data
public class RegisterRequest {
    private String username;
    private String password;
    private Set<String> roles; // e.g. ["ROLE_USER"] or ["ROLE_USER","ROLE_ADMIN"]
}
