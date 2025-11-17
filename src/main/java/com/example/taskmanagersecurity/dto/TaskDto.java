package com.example.taskmanagersecurity.dto;

import lombok.Data;

@Data
public class TaskDto {
    private Long id;
    private String title;
    private String description;
    private String ownerUsername; // optional for responses
}
